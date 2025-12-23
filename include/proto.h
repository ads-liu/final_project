#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stddef.h>

// Header: LEN(4) + OPCODE(2) + FLAGS(1) + RESERVED(1)
#define PROTO_HEADER_LEN   8

// Opcode definitions
#define OPCODE_IMG_REQUEST   0x0001
#define OPCODE_IMG_RESPONSE  0x8001
#define OPCODE_HEARTBEAT     0x0002
#define OPCODE_STATS_QUERY   0x0003
#define OPCODE_STATS_REPLY   0x8003
#define OPCODE_ERROR         0xFFFF

typedef struct {
    uint32_t length;   // Total packet length (header + body)
    uint16_t opcode;
    uint8_t  flags;    // Currently unused, reserved for future extensions
    uint8_t  reserved; // Currently unused
    uint8_t *body;     // Pointer to body buffer
    size_t   body_len; // Body length in bytes
} proto_msg_t;

// Encode proto_msg_t into a sendable buffer, caller must free()
uint8_t *proto_encode(const proto_msg_t *msg, size_t *out_len);

// Parse proto_msg_t from a buffer, returns 0 on success, -1 on failure;
// caller must later call proto_free()
int proto_decode(const uint8_t *buf, size_t buf_len, proto_msg_t *out_msg);

// Free the body buffer inside proto_msg_t
void proto_free(proto_msg_t *msg);

#endif // PROTO_H
