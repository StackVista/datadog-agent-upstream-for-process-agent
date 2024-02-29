#ifndef __AMQP_HELPERS_H
#define __AMQP_HELPERS_H

#include "bpf_endian.h"

#include "protocols/amqp/defs.h"
#include "protocols/amqp/types.h"
#include "protocols/classification/common.h"

// Generalized function to load data from either a packet or a user-space buffer.
// Only set either skb or from, not both.
static __always_inline int amqp_load_data(struct __sk_buff* skb, const void *from, __u32 offset, void *to, __u32 len) {
    if (skb) {
        return bpf_skb_load_bytes_with_telemetry(skb, offset, to, len);
    } else {
        return bpf_probe_read_user(to, len, from + offset);
    }
}

// The method checks if the given buffer includes the protocol header which must be sent in the start of a new connection.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
static __always_inline bool is_amqp_protocol_header(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, sizeof(AMQP_PREFACE));

    bool match = !bpf_memcmp(buf, AMQP_PREFACE, sizeof(AMQP_PREFACE)-1);

    return match;
}

// The method checks if the given buffer is an AMQP message.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
static __always_inline bool is_amqp(conn_tuple_t *tup, const char* buf, __u32 buf_size) {
    // New connection should start with protocol header of AMQP.
    // Ref https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf.
    bool found = is_amqp_protocol_header(buf, buf_size);
    amqp_protocol_identifier *identifier = (amqp_protocol_identifier *)buf;

    if (found) {
        log_debug("is_amqp_protocol_header: protocol version %d.%d.%d", identifier->major, identifier->minor, identifier->revision);
        if (identifier->protocol_id == 0) {
            return true;
        } else {
            // This is an AMQP connection, but it uses an encrypted protocol that we do not support.
            // For pre-established TLS connections, the protocol id is 0.
            log_debug("is_amqp_protocol_header: unsupported protocol id %d", identifier->protocol_id);
            return false;
        }
    }

    // We did not observe the header, but there is still a chance that we are in the middle of a connection.
    // We will use the following heuristic to determine if the packet is an AMQP message:
    // The first bytes of the packet will be parsed as an AMQP frame header, then we check for the frame end marker.
    // If the frame end marker is found, we assume that the packet is an AMQP message.
    if (buf_size < sizeof(amqp_frame_header_t)) {
        log_debug("is_amqp: buffer is too small to contain an AMQP frame header\n");
        return false;
    }

    amqp_frame_header_t *header = (amqp_frame_header_t *)buf;
    __u32 frame_size = bpf_ntohl(header->length) + sizeof(amqp_frame_header_t);

    if (frame_size > 1500) {
        // This may still be a valid AMQP message, but we cannot check that here.
        log_debug("is_amqp: frame size %d is too large for TCP packet\n", frame_size);
        return false;
    }

    if (frame_size > buf_size) {
        log_debug("is_amqp: buffer is too small to check for frame end marker\n");
        return false;
    }

    return buf[frame_size] == '\xce';
}

#endif
