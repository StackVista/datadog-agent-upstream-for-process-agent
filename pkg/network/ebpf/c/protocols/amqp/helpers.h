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
    //
    // For random data to accidentally pass the test, it must
    // 1. Specify a 32bit length within the package size (very unlikely, chance of 1500/2^32)
    // 2. Have the frame end marker at that particular location (unlikely, 1/256)

    if (buf_size < sizeof(amqp_frame_header_t)) {
        return false;
    }

    amqp_frame_header_t *header = (amqp_frame_header_t *)buf;
    __maybe_unused __u32 frame_size = bpf_ntohl(header->length) + sizeof(amqp_frame_header_t);

    if (frame_size > buf_size) {
        // This is not necessarily an error, as we may have received a partial frame, but we
        // cannot look into the next TCP packet to search for the frame end marker.
        return false;
    }

    log_debug("is_amqp: frame size %u", frame_size);

    const unsigned char frame_end_marker = '\xCE';
    unsigned char last_byte = 0;
    long read_error = bpf_probe_read_user(&last_byte, sizeof(last_byte), buf + frame_size);

    if (read_error != 0) {
        log_debug("is_amqp: failed to read the frame end marker. Error: %d\n", read_error);
    } else {
        log_debug("is_amqp: last byte %x", last_byte);
    }

    return last_byte == frame_end_marker;
}

#endif
