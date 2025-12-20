#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int fd;                 // socket file descriptor
} net_conn_t;

// 建立 server 端 listening socket，回傳 fd 或 -1
int net_listen(const char *ip, uint16_t port, int backlog);

// 接受一個連線，回傳新的 fd 或 -1
int net_accept(int listen_fd);

// 建立 client 端連線，回傳 fd 或 -1
int net_connect(const char *ip, uint16_t port);

// 關閉 socket
void net_close(int fd);

// 精準讀/寫指定 bytes（處理 short read/write），成功回傳 0，錯誤 -1
int net_read_n(int fd, void *buf, size_t n);
int net_write_n(int fd, const void *buf, size_t n);

// 設定收/送 timeout（秒），不需要 timeout 可以傳 0
int net_set_recv_timeout(int fd, int seconds);
int net_set_send_timeout(int fd, int seconds);

#ifdef __cplusplus
}
#endif

#endif // NET_H
