#ifndef __AMQP_HELPERS_H
#define __AMQP_HELPERS_H

#include "bpf_endian.h"

#include "protocols/amqp/defs.h"
#include "protocols/classification/common.h"
#include "protocols/amqp/types.h"

// The method checks if the given buffer includes the protocol header which must be sent in the start of a new connection.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
static __always_inline bool is_amqp_protocol_header(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, AMQP_MIN_FRAME_LENGTH);

    bool match = !bpf_memcmp(buf, AMQP_PREFACE, sizeof(AMQP_PREFACE)-1);

    return match;
}

// We could use bpf_probe_read* to do unaligned loads,  but this break on kernel 5.4, most likely due to having trouble proving
// the bounds of the load, hence the plain data loading.
// Story: https://stackstate.atlassian.net/browse/STAC-22744
static __always_inline __u16 load_unaligned_u16(const char* buf) {
  __u16 lower_byte = buf[0];
  __u16 upper_byte = buf[1];
  return lower_byte | (upper_byte << 8);
}

// The method checks if the given buffer is an AMQP message.
// Ref: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
static __always_inline bool is_amqp(const char* buf, __u32 buf_size) {
    // New connection should start with protocol header of AMQP.
    // Ref https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf.
    if (is_amqp_protocol_header(buf, buf_size)) {
        // we also need to check the version.
        amqp_protocol_identifier *identifier = (amqp_protocol_identifier *)buf;
        if (identifier->major == 0 && identifier->minor == 9 && identifier->revision == 1) {
            return true;
        }
        log_debug("is_amqp_protocol_header: Detected protocol %d.%d.%d, this package only supports 0.9.1", identifier->major, identifier->minor, identifier->revision);
        return false;
    }

    // Validate that we will be able to get from the buffer the class and method ids.
    if (buf_size < AMQP_MIN_PAYLOAD_LENGTH) {
        return false;
    }

    __u8 frame_type = buf[0];
    // Check only for method frame type.
    if (frame_type != AMQP_FRAME_METHOD_TYPE) {
        return false;
    }

    // We extract the class id and method id by big endian from the buffer.
    // Ref https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf.
    //
    // We want to read 2 bytes (`hdr->class_id`) from `buf+7`, so an adress potentially not multiple of 2.
    // This could cause misaligned access verifier issues. We use an unaligned load.
    __u16 class_id = bpf_ntohs(load_unaligned_u16(buf + 7));
    __u16 method_id = bpf_ntohs(load_unaligned_u16(buf + 9));

    switch (class_id) {
    case AMQP_CONNECTION_CLASS:
        switch (method_id) {
        case AMQP_METHOD_CONNECTION_START:
        case AMQP_METHOD_CONNECTION_START_OK:
            return true;
        default:
            return false;
        }
    case AMQP_BASIC_CLASS:
        switch (method_id) {
        case AMQP_METHOD_PUBLISH:
        case AMQP_METHOD_DELIVER:
        case AMQP_METHOD_CONSUME:
            return true;
        default:
            return false;
        }
    case AMQP_CHANNEL_CLASS:
        switch (method_id) {
        case AMQP_METHOD_CLOSE_OK:
        case AMQP_METHOD_CLOSE:
            return true;
        default:
            return false;
        }
    default:
        return false;
    }

    /*
    [STS] Custom detection for long lived AMQP connections.
    https://gitlab.com/stackvista/agent/datadog-agent-upstream-for-process-agent/-/merge_requests/20
    Check if the DataDog one is enough or we need to fallback to this one.

    if (tup == NULL)
    {
        // Rest of this code requires a connection tuple.
        return false;
    }

    // We did not observe the header, but there is still a chance that we are in the middle of a connection.
    // We will use the following heuristic to determine if the packet is an AMQP message:
    // The first bytes of the packet will be parsed as an AMQP frame header, then we check for the frame end marker.
    // If the frame end marker is found, we assume that the packet is an AMQP message.
    //
    // For random data to accidentally pass the test, it must
    // 1. Specify a 32bit length within the package size (very unlikely, chance of 1500/2^32)
    // 2. Have the frame end marker at that particular location (unlikely, 1/256)

    // Initialize the evidence if it does not exist.
    __u8 evidence = 50; // 50% - eBPF comiler does not like floats
    bpf_map_update_elem(&amqp_detection_evidence, tup, &evidence, BPF_NOEXIST);

    __u8 *evidence_ptr = bpf_map_lookup_elem(&amqp_detection_evidence, tup);
    if (evidence_ptr == NULL) {
        log_debug("is_amqp: could not load evidence for %u -> %u from map", tup->sport, tup->dport);
        return false;
    }
    evidence = *evidence_ptr;

    amqp_frame_header_t header = {};
    __maybe_unused int error = bpf_load_data(buf_desc, 0, &header, sizeof(amqp_frame_header_t));
    __maybe_unused __u32 frame_size = bpf_ntohl(header.length) + sizeof(amqp_frame_header_t);

    if (frame_size > 1500) {
        // This may be a valid frame, but we cannot look far enough to read the frame end marker.
        // We treat this as a 50/50 chance, though that may be very generous.
        evidence = (evidence + 50) / 2;
    }

    if (frame_size < sizeof(amqp_frame_header_t)) {
        // This is not a valid frame.
        // This makes it very unlikely that this is a valid AMQP frame.
        // But there is a change we are seeing some payload continuation from an earlier packet.
        evidence = (evidence + 20) / 2;
    }

    if (header.frame_type != AMQP_FRAME_METHOD_TYPE && header.frame_type != AMQP_FRAME_TYPE_CONTENT_HEADER && header.frame_type != AMQP_FRAME_TYPE_CONTENT_BODY && header.frame_type != AMQP_FRAME_TYPE_HEARTBEAT) {
        // This is not a valid frame header.
        // Same situation as above: Possible, but very unlikely.
        evidence = (evidence + 20) / 2;
    }

    const unsigned char frame_end_marker = '\xCE';
    unsigned char last_byte = 0;
    error = bpf_load_data(buf_desc, frame_size, &last_byte, 1);

    if (last_byte == frame_end_marker) {
        // We are very confident that this is an AMQP message.
        evidence = (evidence + 100) / 2;
    }

    if (evidence > 90) {
        log_debug("is_amqp: %u -> %u evidence after update: %u%%. Labeling as AMQP.", tup->sport, tup->dport, evidence);
        bpf_map_delete_elem(&amqp_detection_evidence, tup); // No longer needed.
        return true;
    }

    bpf_map_update_elem(&amqp_detection_evidence, tup, &evidence, BPF_ANY);
    return false;
*/
}

#endif
