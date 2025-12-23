// src/tls.c
#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Global TLS/SSL initialization.
 *
 * This should be called once in the process before any TLS client/server
 * contexts are created. It:
 *   - Loads human-readable error strings for OpenSSL.
 *   - Registers available SSL/TLS ciphers and digests.
 */
int tls_global_init(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    return 0;
}

/*
 * Global TLS/SSL cleanup.
 *
 * This can be called when the process is about to exit in order to release
 * resources used by OpenSSL. In newer OpenSSL versions this may be a no-op,
 * but it is kept for compatibility.
 */
void tls_global_cleanup(void) {
    EVP_cleanup();
}

/* ---- Server side helpers ---- */

/*
 * Initialize a TLS server context.
 *
 * Parameters:
 *   s         - Output server context (holds SSL_CTX).
 *   cert_file - Path to the server certificate in PEM format.
 *   key_file  - Path to the corresponding private key in PEM format.
 *
 * Behavior:
 *   - Creates a TLS_server_method() SSL_CTX.
 *   - Loads the certificate and private key from disk.
 *   - Verifies that the private key matches the certificate.
 *
 * Return:
 *   0  on success.
 *  -1  on failure (errors are printed to stderr via ERR_print_errors_fp()).
 */
int tls_server_init(tls_server_t *s, const char *cert_file, const char *key_file) {
    if (!s) return -1;

    const SSL_METHOD *method = TLS_server_method();
    s->ctx = SSL_CTX_new(method);
    if (!s->ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Load server certificate (PEM)
    if (SSL_CTX_use_certificate_file(s->ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(s->ctx);
        s->ctx = NULL;
        return -1;
    }

    // Load server private key (PEM)
    if (SSL_CTX_use_PrivateKey_file(s->ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(s->ctx);
        s->ctx = NULL;
        return -1;
    }

    // Ensure that the private key matches the server certificate
    if (!SSL_CTX_check_private_key(s->ctx)) {
        fprintf(stderr, "Server private key does not match the certificate public key\n");
        SSL_CTX_free(s->ctx);
        s->ctx = NULL;
        return -1;
    }

    return 0;
}

/*
 * Free server TLS context.
 *
 * This releases the SSL_CTX associated with the server.
 * It does not close any active connections (those are handled by tls_close()).
 */
void tls_server_free(tls_server_t *s) {
    if (!s) return;
    if (s->ctx) SSL_CTX_free(s->ctx);
    s->ctx = NULL;
}

/*
 * Wrap an already-accepted TCP file descriptor in a TLS server session.
 *
 * Parameters:
 *   s   - Initialized tls_server_t with a valid SSL_CTX.
 *   fd  - Accepted TCP socket (from accept()).
 *
 * Behavior:
 *   - Creates a new SSL object bound to the server SSL_CTX.
 *   - Attaches the socket descriptor to the SSL object.
 *   - Performs the server-side TLS handshake via SSL_accept().
 *
 * Return:
 *   Pointer to a newly allocated tls_ctx_t on success.
 *   NULL on failure (errors printed to stderr).
 */
tls_ctx_t *tls_server_wrap_fd(tls_server_t *s, int fd) {
    if (!s || !s->ctx) return NULL;

    SSL *ssl = SSL_new(s->ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_set_fd(ssl, fd);

    // Perform the TLS handshake as a server
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

/* ---- Client side helpers ---- */

/*
 * Initialize a TLS client context.
 *
 * Parameters:
 *   c       - Output client context (holds SSL_CTX).
 *   ca_file - Path to a CA bundle / self-signed cert in PEM format, or NULL
 *             to use system default trust store.
 *
 * Behavior:
 *   - Creates a TLS_client_method() SSL_CTX.
 *   - Enables peer verification (SSL_VERIFY_PEER).
 *   - Loads the trust anchors either from ca_file or from the OS defaults. [web:77]
 *
 * Return:
 *   0  on success.
 *  -1  on failure.
 */
int tls_client_init(tls_client_t *c, const char *ca_file) {
    if (!c) return -1;

    const SSL_METHOD *method = TLS_client_method();
    c->ctx = SSL_CTX_new(method);
    if (!c->ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Require verification of the server certificate
    // verify_callback = NULL -> OpenSSL will abort the handshake on failure.
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);

    // Load trusted CA / self-signed certificate
    if (ca_file) {
        if (SSL_CTX_load_verify_locations(c->ctx, ca_file, NULL) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(c->ctx);
            c->ctx = NULL;
            return -1;
        }
    } else {
        // Use system default CA paths (if available) [web:77]
        if (SSL_CTX_set_default_verify_paths(c->ctx) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(c->ctx);
            c->ctx = NULL;
            return -1;
        }
    }

    return 0;
}

/*
 * Free client TLS context.
 *
 * Releases the SSL_CTX created in tls_client_init().
 */
void tls_client_free(tls_client_t *c) {
    if (!c) return;
    if (c->ctx) SSL_CTX_free(c->ctx);
    c->ctx = NULL;
}

/*
 * Wrap a connected TCP socket in a TLS client session.
 *
 * Parameters:
 *   c          - Initialized tls_client_t with a valid SSL_CTX.
 *   fd         - Connected TCP socket descriptor.
 *   servername - Hostname used for SNI and certificate hostname verification.
 *
 * Behavior:
 *   - Creates a new SSL object from c->ctx.
 *   - Associates the socket with SSL via SSL_set_fd().
 *   - Sets Server Name Indication (SNI) so the server can select the right cert.
 *   - Configures OpenSSL to verify that the certificate matches the hostname
 *     (X509_VERIFY_PARAM_set1_host).
 *   - Runs SSL_connect(), which performs:
 *       * TLS handshake
 *       * certificate chain validation
 *       * hostname verification (given the verify settings above). [web:77]
 *
 * Return:
 *   Pointer to a newly allocated tls_ctx_t on success.
 *   NULL on failure.
 */
tls_ctx_t *tls_client_wrap_fd(tls_client_t *c, int fd, const char *servername) {
    if (!c || !c->ctx) return NULL;

    SSL *ssl = SSL_new(c->ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_set_fd(ssl, fd);

    // Configure SNI and hostname verification parameters
    if (servername && servername[0]) {
        // SNI: send the hostname in the ClientHello so virtual hosts can choose a cert
        SSL_set_tlsext_host_name(ssl, servername);

        // Hostname verification: ensure cert CN/SAN matches "servername"
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set1_host(param, servername, 0);
    }

    // Perform client-side TLS handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    // At this point, SSL_connect has verified the certificate according to
    // SSL_CTX_set_verify() and the loaded trust store. [web:77]

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

/* ---- I/O helpers + close ---- */

/*
 * Read exactly n bytes over a TLS connection.
 *
 * Parameters:
 *   t   - TLS context (contains SSL* and underlying fd).
 *   buf - Destination buffer.
 *   n   - Number of bytes to read.
 *
 * Behavior:
 *   - Uses SSL_read() in a loop until n bytes have been read or an error occurs.
 *   - Transparently handles SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE by retrying.
 *   - Returns a special code for clean connection shutdown.
 *
 * Return:
 *   0  on success (read exactly n bytes).
 *   1  if the peer performed a clean TLS shutdown (EOF).
 *  -1  on error (error details printed via ERR_print_errors_fp()).
 */
int tls_read_n(tls_ctx_t *t, void *buf, size_t n) {
    if (!t || !t->ssl || !buf) return -1;

    unsigned char *p = buf;
    size_t left = n;

    while (left > 0) {
        int rd = SSL_read(t->ssl, p, (int)left);
        if (rd <= 0) {
            int err = SSL_get_error(t->ssl, rd);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;   // Non-fatal, retry the operation
            if (err == SSL_ERROR_ZERO_RETURN) {
                return 1;   // Clean shutdown from peer (EOF)
            }
            ERR_print_errors_fp(stderr);
            return -1;
        }
        p    += rd;
        left -= (size_t)rd;
    }

    return 0;               // Successfully read n bytes
}

/*
 * Write exactly n bytes over a TLS connection.
 *
 * Parameters:
 *   t   - TLS context.
 *   buf - Source buffer.
 *   n   - Number of bytes to write.
 *
 * Behavior:
 *   - Uses SSL_write() in a loop until n bytes are sent or a fatal error occurs.
 *   - Retries on SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE.
 *
 * Return:
 *   0  on success (all bytes sent).
 *  -1  on failure (errors printed to stderr).
 */
int tls_write_n(tls_ctx_t *t, const void *buf, size_t n) {
    if (!t || !t->ssl || !buf) return -1;

    const unsigned char *p = buf;
    size_t left = n;

    while (left > 0) {
        int wr = SSL_write(t->ssl, p, (int)left);
        if (wr <= 0) {
            int err = SSL_get_error(t->ssl, wr);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;   // Retry on non-fatal condition
            ERR_print_errors_fp(stderr);
            return -1;
        }
        p    += wr;
        left -= (size_t)wr;
    }

    return 0;
}

/*
 * Gracefully close a TLS connection and free its resources.
 *
 * Behavior:
 *   - Calls SSL_shutdown() to send/receive the TLS close_notify alert.
 *   - Frees the SSL object.
 *   - Closes the underlying TCP socket.
 *   - Frees the tls_ctx_t wrapper.
 */
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
