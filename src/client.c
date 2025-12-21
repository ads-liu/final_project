#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "net.h"
#include "proto.h"
#include "log.h"

typedef struct {
    long total_requests;
    long success_requests;
    double sum_latency_ms;
    double max_latency_ms;
    pthread_mutex_t lock;
} stats_t;

typedef struct {
    const char *ip;
    uint16_t port;
    int requests_per_thread;
    stats_t *stats;
    int thread_index;
    uint8_t *img_body;   // 共用的 lena 請求 body
    size_t body_len;
} thread_arg_t;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t *pixels; // size = width * height
} pgm_img_t;

static double now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

/* 確保有 img 資料夾 */
static void ensure_img_dir(void) {
    struct stat st;
    if (stat("img", &st) == -1) {
        mkdir("img", 0777);
    }
}

/* 儲存 8-bit 灰階像素為 PGM (P5) 檔 */
static void save_pgm(const char *path, const uint8_t *pixels,
                     uint32_t w, uint32_t h) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fprintf(fp, "P5\n%u %u\n255\n", w, h);
    fwrite(pixels, 1, (size_t)w * (size_t)h, fp);
    fclose(fp);
}

/* 產生日期字串 YYYYMMDD */
static void make_date_prefix(char *buf, size_t sz) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, sz, "%Y%m%d", &tmv);
}

/* 讀取 P5 8-bit PGM 檔 (lena.pgm) */
static int load_pgm(const char *path, pgm_img_t *img) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen lena.pgm");
        return -1;
    }

    char magic[3] = {0};
    if (fscanf(fp, "%2s", magic) != 1 || strcmp(magic, "P5") != 0) {
        fprintf(stderr, "not P5 PGM\n");
        fclose(fp);
        return -1;
    }

    int c = fgetc(fp);
    while (c == '#') {              // 跳過註解行
        while (c != '\n' && c != EOF) c = fgetc(fp);
        c = fgetc(fp);
    }
    ungetc(c, fp);

    int w, h, maxval;
    if (fscanf(fp, "%d %d", &w, &h) != 2) {
        fprintf(stderr, "read width/height failed\n");
        fclose(fp);
        return -1;
    }
    if (fscanf(fp, "%d", &maxval) != 1) {
        fprintf(stderr, "read maxval failed\n");
        fclose(fp);
        return -1;
    }
    if (maxval > 255) {
        fprintf(stderr, "only 8-bit PGM supported\n");
        fclose(fp);
        return -1;
    }

    fgetc(fp); // 吃掉 header 後面的單一 whitespace

    size_t pixels = (size_t)w * (size_t)h;
    uint8_t *buf = (uint8_t *)malloc(pixels);
    if (!buf) {
        fprintf(stderr, "malloc pixels failed\n");
        fclose(fp);
        return -1;
    }

    size_t n = fread(buf, 1, pixels, fp);
    fclose(fp);
    if (n != pixels) {
        fprintf(stderr, "fread pixels failed\n");
        free(buf);
        return -1;
    }

    img->width = (uint32_t)w;
    img->height = (uint32_t)h;
    img->pixels = buf;
    return 0;
}

static void *worker_thread(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;

    int fd = net_connect(targ->ip, targ->port);
    if (fd < 0) {
        LOG_ERROR("thread %d connect failed", targ->thread_index);
        return NULL;
    }
    LOG_INFO("thread %d connected fd=%d", targ->thread_index, fd);

    uint8_t *img_body = targ->img_body;
    size_t body_len = targ->body_len;

    uint32_t w_host, h_host;
    memcpy(&w_host, img_body + 0, 4);
    memcpy(&h_host, img_body + 4, 4);
    w_host = ntohl(w_host);
    h_host = ntohl(h_host);

    int saved_once = 0; // 每個 thread 只存一次回傳影像

    for (int i = 0; i < targ->requests_per_thread; ++i) {
        proto_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        msg.opcode   = OPCODE_IMG_REQUEST;
        msg.flags    = 0;
        msg.reserved = 0;
        msg.body     = img_body;
        msg.body_len = body_len;

        size_t out_len = 0;
        uint8_t *out_buf = proto_encode(&msg, &out_len);
        if (!out_buf) {
            LOG_ERROR("proto_encode failed");
            break;
        }

        LOG_INFO("client thread %d sending request %d, len=%zu",
                 targ->thread_index, i, out_len);

        double t1 = now_ms();
        if (net_write_n(fd, out_buf, out_len) < 0) {
            LOG_ERROR("write failed");
            free(out_buf);
            break;
        }

        uint32_t len_net;
        if (net_read_n(fd, &len_net, sizeof(len_net)) < 0) {
            LOG_ERROR("read length failed");
            free(out_buf);
            break;
        }

        uint32_t total_len = ntohl(len_net);
        if (total_len < PROTO_HEADER_LEN) {
            LOG_ERROR("invalid reply length %u", total_len);
            free(out_buf);
            break;
        }

        size_t remaining = total_len - sizeof(len_net);
        uint8_t *in_buf = (uint8_t *)malloc(total_len);
        if (!in_buf) {
            free(out_buf);
            break;
        }
        memcpy(in_buf, &len_net, sizeof(len_net));
        if (net_read_n(fd, in_buf + sizeof(len_net), remaining) < 0) {
            LOG_ERROR("read body failed");
            free(out_buf);
            free(in_buf);
            break;
        }

        proto_msg_t reply;
        if (proto_decode(in_buf, total_len, &reply) < 0) {
            LOG_ERROR("proto_decode failed, total_len=%u", total_len);
            free(out_buf);
            free(in_buf);
            break;
        }

        double t2 = now_ms();
        double lat = t2 - t1;

        pthread_mutex_lock(&targ->stats->lock);
        targ->stats->total_requests++;
        if (reply.opcode == OPCODE_IMG_RESPONSE) {
            targ->stats->success_requests++;
            targ->stats->sum_latency_ms += lat;
            if (lat > targ->stats->max_latency_ms) {
                targ->stats->max_latency_ms = lat;
            }
        }
        pthread_mutex_unlock(&targ->stats->lock);

        /* 每個 thread 第一次成功回應時，把負片存成 img/YYYYMMDD_threadX_lena.pgm */
        if (reply.opcode == OPCODE_IMG_RESPONSE && !saved_once) {
            if (reply.body_len >= 8) {
                uint32_t w_net2, h_net2;
                memcpy(&w_net2, reply.body + 0, 4);
                memcpy(&h_net2, reply.body + 4, 4);
                uint32_t w2 = ntohl(w_net2);
                uint32_t h2 = ntohl(h_net2);

                if ((size_t)w2 * (size_t)h2 + 8 <= reply.body_len) {
                    char date[16];
                    make_date_prefix(date, sizeof(date));

                    char path_after[256];
                    snprintf(path_after, sizeof(path_after),
                             "img/%s_thread%d_lena.pgm",
                             date, targ->thread_index);

                    save_pgm(path_after,
                             (uint8_t *)reply.body + 8, w2, h2);

                    LOG_INFO("thread %d saved reply image to %s",
                             targ->thread_index, path_after);
                    saved_once = 1;
                }
            }
        }

        proto_free(&reply);
        free(out_buf);
        free(in_buf);
    }

    net_close(fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    const char *ip = "127.0.0.1";
    uint16_t port = 9000;
    int threads = 1;
    int req_per_thread = 1;  // 一個 thread 送幾次，可自行調整

    if (argc > 1) ip = argv[1];
    if (argc > 2) port = (uint16_t)atoi(argv[2]);
    if (argc > 3) threads = atoi(argv[3]);
    if (argc > 4) req_per_thread = atoi(argv[4]);

    log_init(NULL, LOG_LEVEL_INFO);

    ensure_img_dir();  // 確保有 img 資料夾

    /* 載入 lena.pgm，組成協定 body */
    pgm_img_t lena;
    if (load_pgm("lena.pgm", &lena) < 0) {
        fprintf(stderr, "load lena.pgm failed\n");
        return 1;
    }

    size_t pixels = (size_t)lena.width * (size_t)lena.height;
    size_t body_len = 8 + pixels;
    uint8_t *img_body = (uint8_t *)malloc(body_len);
    if (!img_body) {
        fprintf(stderr, "malloc img_body failed\n");
        free(lena.pixels);
        return 1;
    }

    uint32_t w_net = htonl(lena.width);
    uint32_t h_net = htonl(lena.height);
    memcpy(img_body + 0, &w_net, 4);
    memcpy(img_body + 4, &h_net, 4);
    memcpy(img_body + 8, lena.pixels, pixels);
    free(lena.pixels);

    stats_t stats;
    memset(&stats, 0, sizeof(stats));
    pthread_mutex_init(&stats.lock, NULL);

    pthread_t *tids = (pthread_t *)malloc(sizeof(pthread_t) * threads);
    thread_arg_t *targs = (thread_arg_t *)malloc(sizeof(thread_arg_t) * threads);
    if (!tids || !targs) {
        fprintf(stderr, "malloc failed\n");
        free(img_body);
        return 1;
    }

    double t_start = now_ms();

    for (int i = 0; i < threads; ++i) {
        targs[i].ip = ip;
        targs[i].port = port;
        targs[i].requests_per_thread = req_per_thread;
        targs[i].stats = &stats;
        targs[i].thread_index = i;
        targs[i].img_body = img_body;
        targs[i].body_len = body_len;
        pthread_create(&tids[i], NULL, worker_thread, &targs[i]);
    }
    for (int i = 0; i < threads; ++i) {
        pthread_join(tids[i], NULL);
    }

    double t_end = now_ms();
    double total_ms = t_end - t_start;

    long total_req = stats.total_requests;
    long succ_req  = stats.success_requests;
    double avg_lat = succ_req > 0 ? stats.sum_latency_ms / succ_req : 0.0;
    double throughput = total_ms > 0 ? (double)succ_req / (total_ms / 1000.0) : 0.0;

    printf("Total requests:   %ld\n", total_req);
    printf("Success requests: %ld\n", succ_req);
    printf("Avg latency:      %.3f ms\n", avg_lat);
    printf("Max latency:      %.3f ms\n", stats.max_latency_ms);
    printf("Throughput:       %.3f req/s\n", throughput);

    pthread_mutex_destroy(&stats.lock);
    free(tids);
    free(targs);
    free(img_body);
    log_close();
    return 0;
}
