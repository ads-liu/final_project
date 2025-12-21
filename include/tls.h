// include/tls.h
#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stddef.h>

typedef struct tls_ctx {
    SSL  *ssl;
    int   fd;
} tls_ctx_t;

/* ---- 共用初始化 ---- */
int tls_global_init(void);     // 初始化 OpenSSL（只要呼叫一次）
void tls_global_cleanup(void); // 可不用特別呼叫，結束前呼叫也行

/* ---- Server 端 ---- */
typedef struct tls_server {
    SSL_CTX *ctx;
} tls_server_t;

// cert_file = server.crt, key_file = server.key
int  tls_server_init(tls_server_t *s, const char *cert_file, const char *key_file);
void tls_server_free(tls_server_t *s);

// 針對已經 accept() 得到的 fd 包 TLS（做 SSL_accept）
tls_ctx_t *tls_server_wrap_fd(tls_server_t *s, int fd);

/* ---- Client 端 ---- */
typedef struct tls_client {
    SSL_CTX *ctx;
} tls_client_t;

// ca_file: 要信任的 CA 或 self-signed cert，例如 "server.crt"
int  tls_client_init(tls_client_t *c, const char *ca_file);
void tls_client_free(tls_client_t *c);

// fd: 已經 connect() 成功的 TCP fd
// servername: 用來做 SNI + hostname 驗證，可填 "127.0.0.1" 或你的域名
tls_ctx_t *tls_client_wrap_fd(tls_client_t *c, int fd, const char *servername);

/* ---- 資料收發與關閉 ---- */
int  tls_read_n(tls_ctx_t *t, void *buf, size_t n);
int  tls_write_n(tls_ctx_t *t, const void *buf, size_t n);
void tls_close(tls_ctx_t *t);

#endif
