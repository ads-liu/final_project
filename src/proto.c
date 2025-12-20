#include "proto.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

uint8_t *proto_encode(const proto_msg_t *msg, size_t *out_len) {
    if (!msg || !out_len) return NULL;

    uint32_t total_len = PROTO_HEADER_LEN + (uint32_t)msg->body_len;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return NULL;

    uint32_t len_net = htonl(total_len);
    uint16_t op_net  = htons(msg->opcode);

    // LEN + OPCODE
    memcpy(buf + 0, &len_net, 4);
    memcpy(buf + 4, &op_net,  2);

    // FLAGS + RESERVED
    buf[6] = msg->flags;
    buf[7] = msg->reserved;

    // BODY
    if (msg->body && msg->body_len > 0) {
        memcpy(buf + PROTO_HEADER_LEN, msg->body, msg->body_len);
    }

    *out_len = total_len;
    return buf;
}

int proto_decode(const uint8_t *buf, size_t buf_len, proto_msg_t *out_msg) {
    if (!buf || !out_msg || buf_len < PROTO_HEADER_LEN) return -1;

    uint32_t len_net;
    uint16_t op_net;
    memcpy(&len_net, buf + 0, 4);
    memcpy(&op_net,  buf + 4, 2);

    uint32_t total_len = ntohl(len_net);
    if (total_len != buf_len) {
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

void proto_free(proto_msg_t *msg) {
    if (!msg) return;
    if (msg->body) {
        free(msg->body);
        msg->body = NULL;
    }
    msg->body_len = 0;
}
