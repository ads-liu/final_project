#include "tls_wrapper.h"
#include "net.h"

#include <stdlib.h>
#include <string.h>

// 目前先用最簡單的假 TLS：直接呼叫 net_*
// 之後若真的接 TLSe，可以在這裡包含 tlse.c 並映射 API

struct tls_ctx {
    int fd;
};

int tls_global_init(void) {
    // 若用 LibTomCrypt / TLSe，這裡會註冊 cipher、PRNG 等
    return 0;
}

tls_ctx_t *tls_server_create(int fd) {
    tls_ctx_t *ctx = (tls_ctx_t *)malloc(sizeof(tls_ctx_t));
    if (!ctx) return NULL;
    ctx->fd = fd;
    return ctx;
}

tls_ctx_t *tls_client_create(int fd) {
    tls_ctx_t *ctx = (tls_ctx_t *)malloc(sizeof(tls_ctx_t));
    if (!ctx) return NULL;
    ctx->fd = fd;
    return ctx;
}

int tls_handshake(tls_ctx_t *ctx) {
    (void)ctx;
    // 真正 TLS 會在這裡做 handshake
    return 0;
}

int tls_read_n(tls_ctx_t *ctx, void *buf, size_t n) {
    return net_read_n(ctx->fd, buf, n);
}

int tls_write_n(tls_ctx_t *ctx, const void *buf, size_t n) {
    return net_write_n(ctx->fd, buf, n);
}

void tls_close(tls_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx);
}
