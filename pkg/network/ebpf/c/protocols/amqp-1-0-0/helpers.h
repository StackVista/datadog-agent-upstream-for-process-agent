#ifndef __AMQP_1_0_0_HELPERS_H
#define __AMQP_1_0_0_HELPERS_H

#include "bpf_endian.h"
#include "bpf_unified_buffer_access.h"

#include "protocols/amqp/types.h" // For amqp_protocol_identifier
#include "protocols/amqp-1-0-0/types.h"
#include "protocols/amqp-1-0-0/parsing-maps.h"
#include "protocols/classification/common.h"

// The method checks if the given buffer includes the protocol header which must be sent in the start of a new connection.
static __always_inline bool is_amqp_1_0_0_protocol_header(const bpf_buffer_desc_t *buf_desc) {
    amqp_protocol_identifier identifier;
    __maybe_unused int error = bpf_load_data(buf_desc, 0, &identifier, sizeof(amqp_protocol_identifier));
    bool match = !bpf_memcmp(AMQP_PREFACE, identifier.preamble, sizeof(AMQP_PREFACE));
    if (match) {
        if (identifier.major == 1 && identifier.minor == 0) {
            return true;
        } else {
            log_debug("is_amqp_1_0_0_protocol_header: Detected protocol %d.%d.%d, this package only supports 1.0.x", identifier.major, identifier.minor, identifier.revision);
        }
    }
    return false;
}

// The method checks if the given buffer is an AMQP 1.0.x message.
// This method will do multiple reads from the buffer to determine if the buffer is an AMQP message.
static __always_inline bool is_amqp_1_0_0(conn_tuple_t *tup, const bpf_buffer_desc_t *buf_desc) {   
    bool found = is_amqp_1_0_0_protocol_header(buf_desc);

    if (found) {
        // Seen the connection prefix, so no need for further checks.
        return true;
    }

    if (tup == NULL)
    {
        // Rest of this code requires a connection tuple.
        return false;
    }

    // We did not observe the header, but there is still a chance that we are in the middle of a connection.
    // Sadly, AMQP 1.0.x does not have a clear end marker, so we need to rely on the structure of the protocol.
    // We use various heuristics based on observed data to detect the protocol.

    // Initialize the evidence if it does not exist.
    __u8 evidence = 50; // 50% - eBPF comiler does not like floats
    bpf_map_update_elem(&amqp_1_0_0_detection_evidence, tup, &evidence, BPF_NOEXIST);

    __u8 *evidence_ptr = bpf_map_lookup_elem(&amqp_1_0_0_detection_evidence, tup);
    if (evidence_ptr == NULL) {
        log_debug("is_amqp_1_0_0: could not load evidence for %u -> %u from map", tup->sport, tup->dport);
        return false;
    }
    evidence = *evidence_ptr;

    amqp_1_0_0_frame_header_t header = {};
    __maybe_unused int error = bpf_load_data(buf_desc, 0, &header, sizeof(amqp_1_0_0_frame_header_t));
    __maybe_unused __u32 frame_size = bpf_ntohl(header.length);

    // By default, we gain evidence from every new packet.
    // Further below, we will reduce the evidence if we find something that is not consistent with an AMQP frame.
    evidence = (evidence + 100) / 2;

    if (frame_size > 1500) {
        // This may be a valid frame, but we cannot look far enough to read the frame end marker.
        // We treat this as a 50/50 chance, though that may be very generous.
        evidence = (evidence + 50) / 2;
    }

    if (frame_size < sizeof(amqp_frame_header_t)) {
        // If this is indeed the size field of an AMQP frame header, it is not a valid frame.
        // This makes it very unlikely that this is a valid AMQP frame.
        // But there is a change we are seeing some payload continuation from an earlier packet.
        evidence = (evidence + 20) / 2;
    }

    if (header.doff < 2) {
        // This is not a valid AMQP frame header.
        // This makes it very unlikely that this is a valid AMQP frame.
        evidence = (evidence + 20) / 2;
    }

    if (header.type != 0) {
        // This is not a valid AMQP frame header.
        // This makes it very unlikely that this is a valid AMQP frame.
        evidence = (evidence + 20) / 2;
    }

    if (header.doff * 4 > frame_size) {
        // This is not a valid AMQP frame header.
        // This makes it very unlikely that this is a valid AMQP frame.
        evidence = (evidence + 20) / 2;
    }   

    if (evidence > 90) {
        log_debug("is_amqp_1_0_0: %u -> %u evidence after update: %u%%. Labeling as AMQP 1.0.0.", tup->sport, tup->dport, evidence);
        bpf_map_delete_elem(&amqp_detection_evidence, tup); // No longer needed.
        return true;
    }

    bpf_map_update_elem(&amqp_detection_evidence, tup, &evidence, BPF_ANY);
    return false;
}

#endif
