#ifndef TLS_WRAPPER_H
#define TLS_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_ctx tls_ctx_t;

// 初始化 TLS library（載入隨機數、註冊 cipher 等），成功回傳 0
int tls_global_init(void);

// 建立 server 端 TLS context，參數可放證書路徑（先留白）
tls_ctx_t *tls_server_create(int fd);
tls_ctx_t *tls_client_create(int fd);

// 做 TLS handshake，成功 0
int tls_handshake(tls_ctx_t *ctx);

// TLS 版 read/write，語意跟 net_read_n / net_write_n 類似
int tls_read_n(tls_ctx_t *ctx, void *buf, size_t n);
int tls_write_n(tls_ctx_t *ctx, const void *buf, size_t n);

// 關閉與釋放
void tls_close(tls_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif // TLS_WRAPPER_H
