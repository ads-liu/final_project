// include/tls.h
#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stddef.h>

typedef struct tls_ctx {
    SSL *ssl;
    int  fd;
} tls_ctx_t;

/* ---- Global initialization ---- */
int  tls_global_init(void);      // Initialize OpenSSL (call once)
void tls_global_cleanup(void);   // Optional; can be called before program exit

/* ---- Server side ---- */
typedef struct tls_server {
    SSL_CTX *ctx;
} tls_server_t;

// cert_file = server certificate (e.g. "server.crt"), key_file = server private key (e.g. "server.key")
int  tls_server_init(tls_server_t *s, const char *cert_file, const char *key_file);
void tls_server_free(tls_server_t *s);

// Wrap an already-accepted fd with TLS (performs SSL_accept)
tls_ctx_t *tls_server_wrap_fd(tls_server_t *s, int fd);

/* ---- Client side ---- */
typedef struct tls_client {
    SSL_CTX *ctx;
} tls_client_t;

// ca_file: trusted CA or self-signed certificate, e.g. "server.crt"
int  tls_client_init(tls_client_t *c, const char *ca_file);
void tls_client_free(tls_client_t *c);

// fd: TCP fd that has already successfully connect()'ed
// servername: used for SNI + hostname verification, e.g. "127.0.0.1" or your domain name
tls_ctx_t *tls_client_wrap_fd(tls_client_t *c, int fd, const char *servername);

/* ---- Data I/O and close ---- */
int  tls_read_n(tls_ctx_t *t, void *buf, size_t n);
int  tls_write_n(tls_ctx_t *t, const void *buf, size_t n);
void tls_close(tls_ctx_t *t);

#endif
