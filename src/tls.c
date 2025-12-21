// src/tls.c
#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int tls_global_init(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    return 0;
}

void tls_global_cleanup(void) {
    EVP_cleanup();
}

/* ---- Server ---- */

int tls_server_init(tls_server_t *s, const char *cert_file, const char *key_file) {
    if (!s) return -1;

    const SSL_METHOD *method = TLS_server_method();
    s->ctx = SSL_CTX_new(method);
    if (!s->ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 載入 server 憑證與私鑰
    if (SSL_CTX_use_certificate_file(s->ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(s->ctx);
        s->ctx = NULL;
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(s->ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(s->ctx);
        s->ctx = NULL;
        return -1;
    }

    if (!SSL_CTX_check_private_key(s->ctx)) {
        fprintf(stderr, "Server private key does not match the certificate public key\n");
        SSL_CTX_free(s->ctx);
        s->ctx = NULL;
        return -1;
    }

    return 0;
}

void tls_server_free(tls_server_t *s) {
    if (!s) return;
    if (s->ctx) SSL_CTX_free(s->ctx);
    s->ctx = NULL;
}

tls_ctx_t *tls_server_wrap_fd(tls_server_t *s, int fd) {
    if (!s || !s->ctx) return NULL;

    SSL *ssl = SSL_new(s->ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_set_fd(ssl, fd);

    // 做 TLS Handshake（server 端）
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    tls_ctx_t *t = (tls_ctx_t *)calloc(1, sizeof(tls_ctx_t));
    if (!t) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }

    t->ssl = ssl;
    t->fd  = fd;
    return t;
}

/* ---- Client ---- */

int tls_client_init(tls_client_t *c, const char *ca_file) {
    if (!c) return -1;

    const SSL_METHOD *method = TLS_client_method();
    c->ctx = SSL_CTX_new(method);
    if (!c->ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // 要驗證 server 憑證
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL); // verify_callback = NULL，失敗就直接中斷 [web:43][web:50]

    // 載入信任的 CA / self-signed cert
    if (ca_file) {
        if (SSL_CTX_load_verify_locations(c->ctx, ca_file, NULL) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(c->ctx);
            c->ctx = NULL;
            return -1;
        }
    } else {
        if (SSL_CTX_set_default_verify_paths(c->ctx) != 1) { // 用系統預設 CA（如果有）[web:25][web:46]
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(c->ctx);
            c->ctx = NULL;
            return -1;
        }
    }

    return 0;
}

void tls_client_free(tls_client_t *c) {
    if (!c) return;
    if (c->ctx) SSL_CTX_free(c->ctx);
    c->ctx = NULL;
}

tls_ctx_t *tls_client_wrap_fd(tls_client_t *c, int fd, const char *servername) {
    if (!c || !c->ctx) return NULL;

    SSL *ssl = SSL_new(c->ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_set_fd(ssl, fd);

    // SNI + hostname 驗證參數（對應 X509_check_host / X509_VERIFY_PARAM_set1_host）[web:26][web:29][web:23]
    if (servername && servername[0]) {
        SSL_set_tlsext_host_name(ssl, servername);
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set1_host(param, servername, 0);
    }

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    // 這裡 SSL_connect 會根據 SSL_CTX_set_verify + trust store 檢查 server cert [web:43][web:47]

    tls_ctx_t *t = (tls_ctx_t *)calloc(1, sizeof(tls_ctx_t));
    if (!t) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }

    t->ssl = ssl;
    t->fd  = fd;
    return t;
}

/* ---- I/O + close ---- */

int tls_read_n(tls_ctx_t *t, void *buf, size_t n) {
    if (!t || !t->ssl || !buf) return -1;

    unsigned char *p = buf;
    size_t left = n;

    while (left > 0) {
        int rd = SSL_read(t->ssl, p, (int)left);
        if (rd <= 0) {
            int err = SSL_get_error(t->ssl, rd);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            if (err == SSL_ERROR_ZERO_RETURN) {
                return 1; // EOF / 對端關閉
            }
            ERR_print_errors_fp(stderr);
            return -1;
        }
        p += rd;
        left -= (size_t)rd;
    }

    return 0; // 讀滿 n bytes
}

int tls_write_n(tls_ctx_t *t, const void *buf, size_t n) {
    if (!t || !t->ssl || !buf) return -1;

    const unsigned char *p = buf;
    size_t left = n;

    while (left > 0) {
        int wr = SSL_write(t->ssl, p, (int)left);
        if (wr <= 0) {
            int err = SSL_get_error(t->ssl, wr);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            ERR_print_errors_fp(stderr);
            return -1;
        }
        p += wr;
        left -= (size_t)wr;
    }

    return 0;
}

void tls_close(tls_ctx_t *t) {
    if (!t) return;
    if (t->ssl) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
    }
    if (t->fd >= 0) {
        close(t->fd);
    }
    free(t);
}
