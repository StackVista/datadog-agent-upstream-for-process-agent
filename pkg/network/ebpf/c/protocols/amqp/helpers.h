#ifndef __AMQP_HELPERS_H
#define __AMQP_HELPERS_H

#include "bpf_endian.h"

#include "protocols/amqp/defs.h"
#include "protocols/amqp/types.h"
#include "protocols/classification/common.h"

// The method checks if the given buffer includes the protocol header which must be sent in the start of a new connection.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
static __always_inline bool is_amqp_protocol_header(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, AMQP_MIN_FRAME_LENGTH);

    bool match = !bpf_memcmp(buf, AMQP_PREFACE, sizeof(AMQP_PREFACE)-1);

    return match;
}

// The method checks if the given buffer is an AMQP message.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
// STS/JGT: This has been deliberately simplified to only check for the protocol header.
// We will not care about connections that are already established when the agent starts,
// since we need to track some state for which we need to see the initial connection.
static __always_inline bool is_amqp(conn_tuple_t *tup, const char* buf, __u32 buf_size) {
    // New connection should start with protocol header of AMQP.
    // Ref https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf.
    bool found = is_amqp_protocol_header(buf, buf_size);

    if (found) {
        __maybe_unused amqp_protocol_identifier *identifier = (amqp_protocol_identifier *)buf;
        log_debug("is_amqp_protocol_header: protocol version %d.%d.%d", identifier->major, identifier->minor, identifier->revision);
    }

    return found;
}

#endif
