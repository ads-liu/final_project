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

static void handle_sigint(int signo) {
    (void)signo;
    if (g_ipc.stats) {
        ipc_lock(&g_ipc);
        g_ipc.stats->shutdown_flag = 1;
        ipc_unlock(&g_ipc);
    }
}

// 主功能：處理 image request
// body 格式: [w(4)][h(4)][pixels...], 灰階 8-bit
static void process_image_request(const proto_msg_t *req, proto_msg_t *reply) {
    if (!req || !reply) return;

    if (req->body_len < 8) {
        const char *err = "invalid img body";
        reply->opcode = OPCODE_ERROR;
        reply->flags  = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
        return;
    }

    uint32_t w_net, h_net;
    memcpy(&w_net, req->body + 0, 4);
    memcpy(&h_net, req->body + 4, 4);
    uint32_t w = ntohl(w_net);
    uint32_t h = ntohl(h_net);
    size_t pixels = (size_t)w * (size_t)h;

    if (req->body_len != 8 + pixels) {
        const char *err = "size mismatch";
        reply->opcode = OPCODE_ERROR;
        reply->flags  = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
        return;
    }

    uint8_t *out_body = (uint8_t *)malloc(req->body_len);
    if (!out_body) {
        const char *err = "oom";
        reply->opcode = OPCODE_ERROR;
        reply->flags  = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
        return;
    }

    // 複製 width/height
    memcpy(out_body, req->body, 8);

    uint8_t *in_pixels  = req->body + 8;
    uint8_t *out_pixels = out_body + 8;

    /* --------- Unsharp Mask 開始：I_sharp = I + k*(I - blur(I)) --------- */

    // 1. 先做一張模糊圖（3x3 box blur）
    uint8_t *blur = (uint8_t *)malloc(pixels);
    if (!blur) {
        free(out_body);
        const char *err = "oom";
        reply->opcode = OPCODE_ERROR;
        reply->flags  = 0;
        reply->reserved = 0;
        reply->body_len = strlen(err);
        reply->body = (uint8_t *)malloc(reply->body_len);
        if (reply->body) memcpy(reply->body, err, reply->body_len);
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

    // 2. Unsharp: I_sharp = I + k*(I - B)
    float k = 10.0f; // 銳化強度，可調整
    for (size_t i = 0; i < pixels; ++i) {
        int orig   = in_pixels[i];
        int b      = blur[i];
        int detail = orig - b;
        int val    = (int)(orig + k * detail);
        if (val < 0)   val = 0;
        if (val > 255) val = 255;
        out_pixels[i]  = (uint8_t)val;
    }

    free(blur);

    /* --------- Unsharp Mask 結束 --------- */

    reply->opcode   = OPCODE_IMG_RESPONSE;
    reply->flags    = 0;
    reply->reserved = 0;
    reply->body     = out_body;
    reply->body_len = req->body_len;
}

static void handle_connection(int conn_fd) {
    LOG_INFO("handle_connection start fd=%d", conn_fd);

    for (;;) {
        uint32_t len_net;
        if (net_read_n(conn_fd, &len_net, sizeof(len_net)) < 0) {
            LOG_WARN("server read length failed");
            break;
        }

        uint32_t total_len = ntohl(len_net);
        if (total_len < PROTO_HEADER_LEN || total_len > (10 * 1024 * 1024)) {
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
        g_ipc.stats->total_requests++;
        g_ipc.stats->total_bytes_in += msg.body_len;
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
        g_ipc.stats->total_bytes_out += reply.body_len;
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
        if (g_ipc.stats && g_ipc.stats->shutdown_flag) {
            LOG_INFO("worker %d detected shutdown_flag", getpid());
            break;
        }

        int conn_fd = net_accept(listen_fd);
        if (conn_fd < 0) {
            if (g_ipc.stats && g_ipc.stats->shutdown_flag) break;
            continue;
        }

        LOG_INFO("worker %d accepted connection", getpid());
        handle_connection(conn_fd);
    }

    LOG_INFO("worker %d exit", getpid());
}

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

    for (int i = 0; i < workers; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_loop(listen_fd);
            close(listen_fd);
            exit(0);
        }
    }

    for (;;) {
        if (g_ipc.stats && g_ipc.stats->shutdown_flag) {
            LOG_INFO("master detected shutdown_flag");
            break;
        }
        sleep(1);
    }

    close(listen_fd);

    int status;
    while (waitpid(-1, &status, 0) > 0) {}

    ipc_destroy(&g_ipc);
    log_close();
    return 0;
}
