#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <errno.h>

#include "net.h"
#include "proto.h"
#include "ipc.h"
#include "log.h"
#include "tls.h"

#define SHM_KEY 0x12340001
#define SEM_KEY 0x12340002

static ipc_handle_t g_ipc;
#define STATS (g_ipc.stats)

#define MAX_IMG_PIXELS (512*512)

// TLS server context (shared by all workers)
static tls_server_t g_tls_server;

/* ========= signal handling ========= */

static void handle_sigint(int signo) {
    (void)signo;
    if (g_ipc.stats) {
        ipc_lock(&g_ipc);
        STATS->shutdown_flag = 1;
        ipc_unlock(&g_ipc);
    }
}

/* ========= Unsharp process: process jobs in shared memory ========= */

static void do_unsharp_job(job_t *job) {
    uint32_t w = job->width;
    uint32_t h = job->height;
    size_t pixels = job->pixels;
    uint8_t *in_pixels = job->input;
    uint8_t *out_pixels = job->output;

    uint8_t *blur = (uint8_t *)malloc(pixels);
    if (!blur) {
        memcpy(out_pixels, in_pixels, pixels);
        return;
    }

    // Simple 3x3 box blur
    for (uint32_t y = 0; y < h; ++y) {
        for (uint32_t x = 0; x < w; ++x) {
            int sum = 0;
            int cnt = 0;
            for (int dy = -1; dy <= 1; ++dy) {
                int yy = (int)y + dy;
                if (yy < 0 || yy >= (int)h) continue;
                for (int dx = -1; dx <= 1; ++dx) {
                    int xx = (int)x + dx;
                    if (xx < 0 || xx >= (int)w) continue;
                    sum += in_pixels[yy * w + xx];
                    cnt++;
                }
            }
            blur[y * w + x] = (uint8_t)(sum / cnt);
        }
    }

    // Unsharp mask: output = orig + k * (orig - blur)
    float k = 8.0f;
    for (size_t i = 0; i < pixels; ++i) {
        int orig = in_pixels[i];
        int b = blur[i];
        int detail = orig - b;
        int val = (int)(orig + k * detail);
        if (val < 0) val = 0;
        if (val > 255) val = 255;
        out_pixels[i] = (uint8_t)val;
    }

    free(blur);
}

static void unsharp_loop(void) {
    pid_t mypid = getpid();
    LOG_INFO("unsharp process %d started", mypid);

    while (1) {
        ipc_lock(&g_ipc);
        if (STATS->shutdown_flag) {
            ipc_unlock(&g_ipc);
            break;
        }

        int found = 0;
        job_t *job = NULL;

        // Find a READY job, mark it BUSY and set owner_pid
        for (int i = 0; i < MAX_JOBS; ++i) {
            job_t *j = &STATS->jobs[i];
            if (j->state == JOB_READY) {
                j->state     = JOB_BUSY;   // Mark as JOB_BUSY
                j->owner_pid = mypid;      // Record which unsharp process is handling it
                job = j;
                found = 1;
                break;
            }
        }
        ipc_unlock(&g_ipc);

        if (!found) {
            usleep(1000);
            continue;
        }

        // Perform unsharp processing
        do_unsharp_job(job);

        // Write back as DONE
        ipc_lock(&g_ipc);
        job->state = JOB_DONE;
        // owner_pid can stay for debugging; clear to 0 if needed
        ipc_unlock(&g_ipc);
    }

    LOG_INFO("unsharp process %d exit", mypid);
}

/* ========= Worker side: submit jobs to unsharp process ========= */

// body: [w(4)][h(4)][pixels...]
static int submit_unsharp_job(uint32_t w, uint32_t h,
                              const uint8_t *in_pixels,
                              job_t **ret_job) {
    size_t pixels = (size_t)w * (size_t)h;
    if (pixels > MAX_IMG_PIXELS) {
        return -1;
    }

    while (1) {
        ipc_lock(&g_ipc);
        if (STATS->shutdown_flag) {
            ipc_unlock(&g_ipc);
            return -1;
        }

        int slot = -1;
        for (int i = 0; i < MAX_JOBS; ++i) {
            if (STATS->jobs[i].state == JOB_EMPTY) {
                slot = i;
                break;
            }
        }

        if (slot >= 0) {
            job_t *job = &STATS->jobs[slot];
            job->width  = w;
            job->height = h;
            job->pixels = pixels;
            memcpy(job->input, in_pixels, pixels);
            job->state     = JOB_READY;
            job->owner_pid = 0;   // Clear owner before submission
            *ret_job = job;
            ipc_unlock(&g_ipc);
            return 0;
        }

        ipc_unlock(&g_ipc);
        usleep(1000);
    }
}

// Wait for job to finish (DONE), then build reply body (including w, h header)
static int wait_unsharp_and_build_reply(job_t *job,
                                        const proto_msg_t *req,
                                        proto_msg_t *reply) {
    while (1) {
        ipc_lock(&g_ipc);
        if (STATS->shutdown_flag) {
            ipc_unlock(&g_ipc);
            return -1;
        }

        if (job->state == JOB_DONE) {
            ipc_unlock(&g_ipc);
            break;
        }

        ipc_unlock(&g_ipc);
        usleep(1000);
    }

    size_t pixels = job->pixels;
    size_t body_len = 8 + pixels;
    uint8_t *out_body = (uint8_t *)malloc(body_len);
    if (!out_body) {
        return -1;
    }

    memcpy(out_body, req->body, 8);
    memcpy(out_body + 8, job->output, pixels);

    ipc_lock(&g_ipc);
    job->state     = JOB_EMPTY;
    job->owner_pid = 0;   // Clear owner
    ipc_unlock(&g_ipc);

    reply->opcode   = OPCODE_IMG_RESPONSE;
    reply->flags    = 0;
    reply->reserved = 0;
    reply->body     = out_body;
    reply->body_len = body_len;
    return 0;
}

// Parse body, submit a job to the unsharp process, then retrieve the result
static void process_image_request(const proto_msg_t *req, proto_msg_t *reply) {
    if (!req || !reply) return;

    if (req->body_len < 8) {
        const char *err = "invalid img body";
        reply->opcode   = OPCODE_ERROR;
        reply->flags    = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body     = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
        return;
    }

    uint32_t w_net, h_net;
    memcpy(&w_net, req->body + 0, 4);
    memcpy(&h_net, req->body + 4, 4);
    uint32_t w = ntohl(w_net);
    uint32_t h = ntohl(h_net);
    size_t pixels = (size_t)w * (size_t)h;
    if (req->body_len != 8 + pixels || pixels > MAX_IMG_PIXELS) {
        const char *err = "size mismatch";
        reply->opcode   = OPCODE_ERROR;
        reply->flags    = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body     = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
        return;
    }

    uint8_t *in_pixels = req->body + 8;
    job_t *job = NULL;
    if (submit_unsharp_job(w, h, in_pixels, &job) < 0) {
        const char *err = "job submit failed";
        reply->opcode   = OPCODE_ERROR;
        reply->flags    = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body     = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
        return;
    }

    if (wait_unsharp_and_build_reply(job, req, reply) < 0) {
        const char *err = "job wait failed";
        reply->opcode   = OPCODE_ERROR;
        reply->flags    = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body     = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
        return;
    }
}

/* ========= handle_connection / worker_loop (TLS version) ========= */

static void handle_connection(tls_ctx_t *t) {
    if (!t) return;
    LOG_INFO("handle_connection start fd=%d", t->fd);

    for (;;) {
        uint32_t len_net;
        int r = tls_read_n(t, &len_net, sizeof(len_net));
        if (r != 0) {
            if (r == 1) {
                LOG_INFO("client closed connection fd=%d", t->fd);
            } else {
                LOG_WARN("server read length failed fd=%d", t->fd);
            }
            break;
        }

        uint32_t total_len = ntohl(len_net);
        if (total_len < PROTO_HEADER_LEN) {
            LOG_WARN("invalid packet length %u", total_len);
            break;
        }

        size_t remaining = total_len - sizeof(len_net);
        uint8_t *buf = (uint8_t *)malloc(total_len);
        if (!buf) {
            LOG_ERROR("malloc failed");
            break;
        }

        memcpy(buf, &len_net, sizeof(len_net));
        if (tls_read_n(t, buf + sizeof(len_net), remaining) < 0) {
            LOG_WARN("server read body failed");
            free(buf);
            break;
        }

        proto_msg_t msg;
        if (proto_decode(buf, total_len, &msg) < 0) {
            LOG_WARN("server proto_decode failed, total_len=%u", total_len);
            free(buf);
            break;
        }
        free(buf);

        LOG_INFO("server got opcode=0x%04x body_len=%zu", msg.opcode, msg.body_len);

        ipc_lock(&g_ipc);
        STATS->total_requests++;
        STATS->total_bytes_in += msg.body_len;
        ipc_unlock(&g_ipc);

        proto_msg_t reply;
        memset(&reply, 0, sizeof(reply));

        if (msg.opcode == OPCODE_IMG_REQUEST) {
            process_image_request(&msg, &reply);
        } else if (msg.opcode == OPCODE_HEARTBEAT) {
            reply.opcode   = OPCODE_HEARTBEAT;
            reply.flags    = 0;
            reply.reserved = 0;
            reply.body     = NULL;
            reply.body_len = 0;
        } else {
            const char *err = "unknown opcode";
            reply.opcode   = OPCODE_ERROR;
            reply.flags    = 0;
            reply.reserved = 0;
            reply.body_len = strlen(err);
            reply.body     = (uint8_t *)malloc(reply.body_len);
            if (reply.body) memcpy(reply.body, err, reply.body_len);
        }

        size_t out_len = 0;
        uint8_t *out_buf = proto_encode(&reply, &out_len);
        if (!out_buf) {
            LOG_ERROR("proto_encode failed");
            proto_free(&msg);
            proto_free(&reply);
            break;
        }

        if (tls_write_n(t, out_buf, out_len) < 0) {
            LOG_WARN("server write failed, out_len=%zu", out_len);
            free(out_buf);
            proto_free(&msg);
            proto_free(&reply);
            break;
        }

        free(out_buf);

        ipc_lock(&g_ipc);
        STATS->total_bytes_out += reply.body_len;
        ipc_unlock(&g_ipc);

        proto_free(&msg);
        proto_free(&reply);
    }

    tls_close(t);
    LOG_INFO("handle_connection end fd=%d", t->fd);
}

static void worker_loop(int listen_fd) {
    LOG_INFO("worker %d started", getpid());

    for (;;) {
        ipc_lock(&g_ipc);
        int shutdown = STATS->shutdown_flag;
        ipc_unlock(&g_ipc);
        if (shutdown) {
            LOG_INFO("worker %d detected shutdown_flag", getpid());
            break;
        }

        int conn_fd = net_accept(listen_fd);
        if (conn_fd < 0) {
            ipc_lock(&g_ipc);
            shutdown = STATS->shutdown_flag;
            ipc_unlock(&g_ipc);
            if (shutdown) break;
            continue;
        }

        LOG_INFO("worker %d accepted connection fd=%d", getpid(), conn_fd);

        tls_ctx_t *t = tls_server_wrap_fd(&g_tls_server, conn_fd);
        if (!t) {
            LOG_WARN("tls_server_wrap_fd failed fd=%d", conn_fd);
            net_close(conn_fd);
            continue;
        }

        handle_connection(t);
    }

    LOG_INFO("worker %d exit", getpid());
}

/* ========= main: add unsharp process + TLS initialization ========= */

int main(int argc, char *argv[]) {
    const char *ip = NULL;
    uint16_t port = 9000;
    int workers = 3;

    if (argc > 1) port = (uint16_t)atoi(argv[1]);
    if (argc > 2) workers = atoi(argv[2]);

    log_init(NULL, LOG_LEVEL_INFO);

    if (ipc_create(&g_ipc, SHM_KEY, SEM_KEY) < 0) {
        LOG_ERROR("ipc_create failed");
        return 1;
    }

    tls_global_init();
    if (tls_server_init(&g_tls_server, "server.crt", "server.key") < 0) {
        LOG_ERROR("tls_server_init failed");
        ipc_destroy(&g_ipc);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);

    int listen_fd = net_listen(ip, port, 128);
    if (listen_fd < 0) {
        LOG_ERROR("net_listen failed");
        tls_server_free(&g_tls_server);
        ipc_destroy(&g_ipc);
        return 1;
    }

    // Initialize all job slots
    ipc_lock(&g_ipc);
    for (int i = 0; i < MAX_JOBS; ++i) {
        STATS->jobs[i].state     = JOB_EMPTY;
        STATS->jobs[i].owner_pid = 0;
    }
    ipc_unlock(&g_ipc);

    pid_t unsharp_pid = -1;
    pid_t *worker_pids = calloc(workers, sizeof(pid_t));
    if (!worker_pids) {
        LOG_ERROR("calloc worker_pids failed");
        close(listen_fd);
        tls_server_free(&g_tls_server);
        ipc_destroy(&g_ipc);
        return 1;
    }

    // Fork unsharp process first
    unsharp_pid = fork();
    if (unsharp_pid == 0) {
        close(listen_fd);
        unsharp_loop();
        exit(0);
    } else if (unsharp_pid < 0) {
        LOG_ERROR("fork unsharp failed");
        close(listen_fd);
        free(worker_pids);
        tls_server_free(&g_tls_server);
        ipc_destroy(&g_ipc);
        return 1;
    }

    // Then fork multiple worker processes
    for (int i = 0; i < workers; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_loop(listen_fd);
            close(listen_fd);
            exit(0);
        } else if (pid < 0) {
            LOG_ERROR("fork worker %d failed", i);
            worker_pids[i] = -1;
        } else {
            worker_pids[i] = pid;
        }
    }

    // --- master main loop: monitor shutdown_flag and respawn children ---
    while (1) {
        ipc_lock(&g_ipc);
        int shutdown = STATS->shutdown_flag;
        ipc_unlock(&g_ipc);
        if (shutdown) {
            LOG_INFO("master detected shutdown_flag");
            break;
        }

        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            if (pid == unsharp_pid) {
                LOG_WARN("unsharp process %d exited unexpectedly", pid);

                // Reschedule BUSY jobs handled by the dead unsharp process
                ipc_lock(&g_ipc);
                for (int i = 0; i < MAX_JOBS; ++i) {
                    job_t *job = &STATS->jobs[i];
                    if (job->state == JOB_BUSY && job->owner_pid == pid) {
                        LOG_WARN("requeue job idx=%d owned by dead unsharp %d", i, pid);
                        job->state     = JOB_READY;
                        job->owner_pid = 0;
                    }
                }
                ipc_unlock(&g_ipc);

                ipc_lock(&g_ipc);
                shutdown = STATS->shutdown_flag;
                ipc_unlock(&g_ipc);
                if (!shutdown) {
                    pid_t npid = fork();
                    if (npid == 0) {
                        close(listen_fd);
                        unsharp_loop();
                        exit(0);
                    } else if (npid > 0) {
                        unsharp_pid = npid;
                        LOG_INFO("restarted unsharp process %d", npid);
                    } else {
                        LOG_ERROR("fork unsharp (restart) failed");
                    }
                }
            } else {
                // Restart a worker if it crashes
                for (int i = 0; i < workers; ++i) {
                    if (worker_pids[i] == pid) {
                        LOG_WARN("worker %d (pid=%d) exited", i, pid);
                        ipc_lock(&g_ipc);
                        shutdown = STATS->shutdown_flag;
                        ipc_unlock(&g_ipc);
                        if (!shutdown) {
                            pid_t npid = fork();
                            if (npid == 0) {
                                worker_loop(listen_fd);
                                close(listen_fd);
                                exit(0);
                            } else if (npid > 0) {
                                worker_pids[i] = npid;
                                LOG_INFO("restarted worker %d (pid=%d)", i, npid);
                            } else {
                                LOG_ERROR("fork worker (restart) %d failed", i);
                            }
                        }
                        break;
                    }
                }
            }
        }

        sleep(1);
    }

    // --- shutdown phase ---
    close(listen_fd);
    int status2;
    while (waitpid(-1, &status2, 0) > 0) { }

    free(worker_pids);
    tls_server_free(&g_tls_server);
    tls_global_cleanup();
    ipc_destroy(&g_ipc);
    log_close();
    return 0;
}
