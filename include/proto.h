#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// header: LEN(4) + OPCODE(2) + FLAGS(1) + RESERVED(1)
#define PROTO_HEADER_LEN   8

// opcode 定義
#define OPCODE_IMG_REQUEST   0x0001
#define OPCODE_IMG_RESPONSE  0x8001
#define OPCODE_HEARTBEAT     0x0002
#define OPCODE_STATS_QUERY   0x0003
#define OPCODE_STATS_REPLY   0x8003
#define OPCODE_ERROR         0xFFFF

typedef struct {
    uint32_t length;   // 整包長度 (含 header + body)
    uint16_t opcode;
    uint8_t  flags;    // 目前沒用，保留未來擴充
    uint8_t  reserved; // 目前沒用
    uint8_t *body;     // body buffer
    size_t   body_len; // body 長度
} proto_msg_t;

// 將 proto_msg_t 打包成可傳送的 buffer，呼叫者負責 free()
uint8_t *proto_encode(const proto_msg_t *msg, size_t *out_len);

// 從 buffer 解析出 proto_msg_t，成功回傳 0，失敗 -1；呼叫者最後要 proto_free()
int proto_decode(const uint8_t *buf, size_t buf_len, proto_msg_t *out_msg);

// 釋放 body
void proto_free(proto_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif // PROTO_H
