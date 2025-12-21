#include "net.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int net_listen(const char *ip, uint16_t port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = ip ? inet_addr(ip) : htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}


int net_accept(int listen_fd) {
    return accept(listen_fd, NULL, NULL);
}

int net_connect(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

void net_close(int fd) {
    if (fd >= 0) close(fd);
}

int net_read_n(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t rd = read(fd, p, left);
        if (rd < 0) {
            if (errno == EINTR)
                continue;
            return -1;          // 真正錯誤
        }
        if (rd == 0) {
            return 1;           // 對端正常關閉，視為 EOF
        }
        p    += rd;
        left -= rd;
    }
    return 0;                   // 讀滿 n bytes
}


int net_write_n(int fd, const void *buf, size_t n) {
    size_t total = 0;
    const char *p = (const char *)buf;
    while (total < n) {
        ssize_t ret = write(fd, p + total, n - total);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)ret;
    }
    return 0;
}

int net_set_recv_timeout(int fd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int net_set_send_timeout(int fd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
