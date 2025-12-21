#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "net.h"
#include "proto.h"
#include "ipc.h"
#include "log.h"

#define SHM_KEY 0x12340001
#define SEM_KEY 0x12340002

static ipc_handle_t g_ipc;
#define STATS (g_ipc.stats)

#define MAX_IMG_PIXELS (512*512)   // 看你作業要求，必要時放大一點

/* ========= signal ========= */

static void handle_sigint(int signo) {
    (void)signo;
    if (g_ipc.stats) {
        ipc_lock(&g_ipc);
        STATS->shutdown_flag = 1;
        ipc_unlock(&g_ipc);
    }
}

/* ========= Unsharp process 在 shared memory 上處理 job ========= */

static void do_unsharp_job(job_t *job) {
    uint32_t w = job->width;
    uint32_t h = job->height;
    size_t pixels = job->pixels;

    uint8_t *in_pixels  = job->input;
    uint8_t *out_pixels = job->output;

    uint8_t *blur = (uint8_t *)malloc(pixels);
    if (!blur) {
        // 失敗就原樣 copy 回去
        memcpy(out_pixels, in_pixels, pixels);
        return;
    }

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

    float k = 8.0f;
    for (size_t i = 0; i < pixels; ++i) {
        int orig   = in_pixels[i];
        int b      = blur[i];
        int detail = orig - b;
        int val    = (int)(orig + k * detail);
        if (val < 0)   val = 0;
        if (val > 255) val = 255;
        out_pixels[i] = (uint8_t)val;
    }

    free(blur);
}

static void unsharp_loop(void) {
    LOG_INFO("unsharp process %d started", getpid());

    while (1) {
        ipc_lock(&g_ipc);
        if (STATS->shutdown_flag) {
            ipc_unlock(&g_ipc);
            break;
        }

        int found = 0;
        for (int i = 0; i < 16; ++i) {
            job_t *job = &STATS->jobs[i];
            if (job->state == JOB_READY) {
                // 把狀態先改成暫時值，避免其他 worker 搶
                job->state = JOB_EMPTY + 3; // TEMP_BUSY
                ipc_unlock(&g_ipc);

                do_unsharp_job(job);

                ipc_lock(&g_ipc);
                job->state = JOB_DONE;
                ipc_unlock(&g_ipc);

                found = 1;
                break;
            }
        }

        if (!found) {
            ipc_unlock(&g_ipc);
            usleep(1000); // 沒 job 就小睡一下
        }
    }

    LOG_INFO("unsharp process %d exit", getpid());
}

/* ========= worker 端：丟 job 給 unsharp process ========= */

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
        for (int i = 0; i < 16; ++i) {
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
            job->state = JOB_READY;
            *ret_job = job;
            ipc_unlock(&g_ipc);
            return 0;
        }

        ipc_unlock(&g_ipc);
        // 沒空 slot 就等一下再試
        usleep(1000);
    }
}

// 等 job 變 DONE，然後把 output copy 到 reply body (含 w,h header)
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

    // 複製原本的 w,h
    memcpy(out_body, req->body, 8);
    memcpy(out_body + 8, job->output, pixels);

    ipc_lock(&g_ipc);
    job->state = JOB_EMPTY;
    ipc_unlock(&g_ipc);

    reply->opcode   = OPCODE_IMG_RESPONSE;
    reply->flags    = 0;
    reply->reserved = 0;
    reply->body     = out_body;
    reply->body_len = body_len;

    return 0;
}

// 解析 body，丟 job 給 unsharp，再拿回結果
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

/* ========= handle_connection / worker_loop 幾乎維持原樣 ========= */

static void handle_connection(int conn_fd) {
    LOG_INFO("handle_connection start fd=%d", conn_fd);

    for (;;) {
        uint32_t len_net;
        int r = net_read_n(conn_fd, &len_net, sizeof(len_net));
        if (r != 0) {
            if (r == 1) {
                LOG_INFO("client closed connection fd=%d", conn_fd);
            } else {
                LOG_WARN("server read length failed fd=%d", conn_fd);
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
        if (net_read_n(conn_fd, buf + sizeof(len_net), remaining) < 0) {
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

        if (net_write_n(conn_fd, out_buf, out_len) < 0) {
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

    net_close(conn_fd);
    LOG_INFO("handle_connection end fd=%d", conn_fd);
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

        LOG_INFO("worker %d accepted connection", getpid());
        handle_connection(conn_fd);
    }

    LOG_INFO("worker %d exit", getpid());
}

/* ========= main：多一個 unsharp process ========= */

int main(int argc, char *argv[]) {
    const char *ip = NULL;
    uint16_t port = 9000;
    int workers = 4;

    if (argc > 1) port = (uint16_t)atoi(argv[1]);
    if (argc > 2) workers = atoi(argv[2]);

    log_init(NULL, LOG_LEVEL_INFO);

    if (ipc_create(&g_ipc, SHM_KEY, SEM_KEY) < 0) {
        LOG_ERROR("ipc_create failed");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);

    int listen_fd = net_listen(ip, port, 128);
    if (listen_fd < 0) {
        LOG_ERROR("net_listen failed");
        ipc_destroy(&g_ipc);
        return 1;
    }

    // 初始化 job 狀態
    ipc_lock(&g_ipc);
    for (int i = 0; i < MAX_JOBS; ++i) {
        STATS->jobs[i].state = JOB_EMPTY;
    }
    ipc_unlock(&g_ipc);

    // --- 記錄 child PID ---
    pid_t unsharp_pid = -1;
    pid_t *worker_pids = calloc(workers, sizeof(pid_t));
    if (!worker_pids) {
        LOG_ERROR("calloc worker_pids failed");
        close(listen_fd);
        ipc_destroy(&g_ipc);
        return 1;
    }

    // 先 fork 出 unsharp process
    unsharp_pid = fork();
    if (unsharp_pid == 0) {
        // child: unsharp
        close(listen_fd);
        unsharp_loop();
        exit(0);
    } else if (unsharp_pid < 0) {
        LOG_ERROR("fork unsharp failed");
        close(listen_fd);
        free(worker_pids);
        ipc_destroy(&g_ipc);
        return 1;
    }

    // 再 fork 多個 worker
    for (int i = 0; i < workers; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            // child: worker
            worker_loop(listen_fd);
            close(listen_fd);
            exit(0);
        } else if (pid < 0) {
            LOG_ERROR("fork worker %d failed", i);
            // 簡化處理：master 先繼續跑，少一個 worker
            worker_pids[i] = -1;
        } else {
            worker_pids[i] = pid;
        }
    }

    // master 不用 listen
    // 如果你想保守一點，也可以保留 listen_fd，但不再 accept
    // 這裡先保留，等 shutdown 才 close
    // close(listen_fd); // 如果這樣寫，要在新 fork 的 child 裡重新 net_listen，太麻煩，先不要

    // --- master main loop: 偵測 shutdown_flag + 重生 child ---
    while (1) {
        // 1) 檢查 shutdown_flag
        ipc_lock(&g_ipc);
        int shutdown = STATS->shutdown_flag;
        ipc_unlock(&g_ipc);

        if (shutdown) {
            LOG_INFO("master detected shutdown_flag");
            break;
        }

        // 2) 用 waitpid(WNOHANG) 看看有沒有 child 掛掉
        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            // 查看是誰掛了
            if (pid == unsharp_pid) {
                LOG_WARN("unsharp process %d exited unexpectedly", pid);

                // 如果還沒 shutdown，就重啟 unsharp
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
                // 看是不是某個 worker
                for (int i = 0; i < workers; ++i) {
                    if (worker_pids[i] == pid) {
                        LOG_WARN("worker %d (pid=%d) exited", i, pid);

                        ipc_lock(&g_ipc);
                        shutdown = STATS->shutdown_flag;
                        ipc_unlock(&g_ipc);

                        if (!shutdown) {
                            // 重啟一個新的 worker
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

        // 稍微睡一下，避免 busy loop
        sleep(1);
    }

    // --- 進入 shutdown：不再重生 child，等他們自然結束 ---
    close(listen_fd);

    int status;
    while (waitpid(-1, &status, 0) > 0) {
        // 把所有 child 收乾淨
    }

    free(worker_pids);
    ipc_destroy(&g_ipc);
    log_close();
    return 0;
}
