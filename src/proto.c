#include "proto.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * Encode a proto_msg_t structure into a contiguous byte buffer.
 *
 * Message wire format (big-endian network order):
 *
 *   +------------+------------+--------+----------+---------+
 *   | LEN (4B)   | OPCODE (2) | FLAGS  | RESERVED | BODY... |
 *   +------------+------------+--------+----------+---------+
 *
 *   LEN      : Total length of the message in bytes, including header and body.
 *   OPCODE   : Application-specific operation code (e.g. request/response type).
 *   FLAGS    : Extra flags for the message.
 *   RESERVED : Reserved for future use (currently passed through as-is).
 *   BODY     : Optional payload, msg->body_len bytes.
 *
 * Parameters:
 *   msg     - Input message to encode (header fields + optional body pointer).
 *   out_len - Output: size of the encoded buffer in bytes.
 *
 * Return:
 *   Pointer to a newly allocated buffer containing the encoded message.
 *   Caller is responsible for freeing it with free().
 *   Returns NULL on error (invalid arguments or allocation failure).
 */
uint8_t *proto_encode(const proto_msg_t *msg, size_t *out_len) {
    if (!msg || !out_len) return NULL;

    uint32_t total_len = PROTO_HEADER_LEN + (uint32_t)msg->body_len;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return NULL;

    // Convert multi-byte fields to network byte order
    uint32_t len_net = htonl(total_len);
    uint16_t op_net  = htons(msg->opcode);

    // LEN + OPCODE
    memcpy(buf + 0, &len_net, 4);
    memcpy(buf + 4, &op_net,  2);

    // FLAGS + RESERVED (single bytes, no endian conversion needed)
    buf[6] = msg->flags;
    buf[7] = msg->reserved;

    // BODY (if present)
    if (msg->body && msg->body_len > 0) {
        memcpy(buf + PROTO_HEADER_LEN, msg->body, msg->body_len);
    }

    *out_len = total_len;
    return buf;
}

/*
 * Decode a raw buffer into a proto_msg_t structure.
 *
 * This function:
 *   - Verifies that the embedded LEN field matches buf_len.
 *   - Parses opcode/flags/reserved from the header.
 *   - Allocates a new buffer for the body (if any) and copies it.
 *
 * Parameters:
 *   buf      - Pointer to the received data buffer.
 *   buf_len  - Size of the buffer in bytes.
 *   out_msg  - Output structure to be filled with parsed fields.
 *
 * Ownership:
 *   - On success, out_msg->body is heap-allocated and must be freed
 *     later using proto_free().
 *
 * Return:
 *   0  on success.
 *  -1  on error (invalid length, null pointers, allocation failure, etc.).
 */
int proto_decode(const uint8_t *buf, size_t buf_len, proto_msg_t *out_msg) {
    if (!buf || !out_msg || buf_len < PROTO_HEADER_LEN) return -1;

    uint32_t len_net;
    uint16_t op_net;
    memcpy(&len_net, buf + 0, 4);
    memcpy(&op_net,  buf + 4, 2);

    uint32_t total_len = ntohl(len_net);
    if (total_len != buf_len) {
        // Length field does not match actual buffer size; reject message
        return -1;
    }

    memset(out_msg, 0, sizeof(*out_msg));
    out_msg->length   = total_len;
    out_msg->opcode   = ntohs(op_net);
    out_msg->flags    = buf[6];
    out_msg->reserved = buf[7];

    size_t body_len = buf_len - PROTO_HEADER_LEN;
    if (body_len > 0) {
        out_msg->body = (uint8_t *)malloc(body_len);
        if (!out_msg->body) return -1;
        memcpy(out_msg->body, buf + PROTO_HEADER_LEN, body_len);
        out_msg->body_len = body_len;
    }

    return 0;
}

/*
 * Release dynamically allocated resources inside a proto_msg_t.
 *
 * This does NOT free the proto_msg_t structure itself, only its body buffer.
 * Safe to call multiple times; after the first call body will be NULL
 * and body_len will be reset to 0.
 */
void proto_free(proto_msg_t *msg) {
    if (!msg) return;
    if (msg->body) {
        free(msg->body);
        msg->body = NULL;
    }
    msg->body_len = 0;
}
