#ifndef __MONGO_PARSING_H
#define __MONGO_PARSING_H

#include "bpf_builtins.h"
#include "bpf_telemetry.h"
#include "protocols/mongo/helpers.h"
#include "protocols/mongo/defs.h"
#include "protocols/mongo/types.h"
#include "protocols/mongo/maps.h"
#include "protocols/mongo/usm-events.h"
#include "protocols/classification/common.h"
#include "protocols/classification/dispatcher-maps.h"
#include "protocols/classification/dispatcher-helpers.h"


// This is our entry point for MongoDB over TLS traffic.
// The TLS dispatcher gives a different context from the unencrypted one, so we need to do a little
// dance here get to the mongo header.
SEC("uprobe/mongo_process")
int uprobe__mongo_process(struct pt_regs *ctx) {
    const __u32 zero = 0;
    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);

    if (args == NULL) {
        log_debug("uprobe__mongo_process failed to fetch arguments for tail call\n");
        return 0;
    }

    mongo_msg_header mongo_header = {};
    bpf_probe_read_user_with_telemetry(&mongo_header, MONGO_HEADER_LENGTH, args->buffer_ptr);
    try_parse_mongo_header(&args->tup, (const char *)&mongo_header, MONGO_HEADER_LENGTH); 
    return 0;
}

// Don't be mislead by the name of this function or by the fact that it is in the socket section.
// This will only be called from the dispatcher for packets on connections that have already been
// identified as mongo connections. This is for unencrypted traffic only, for TLS traffic, see
// the uprobe__mongo_process function above.
SEC("socket/mongo_filter")
int socket__mongo_filter(struct __sk_buff* skb) {
    log_debug("socket__mongo_filter: start\n");
    conn_tuple_t tup;
    skb_info_t skb_info;

    if (!fetch_dispatching_arguments(&tup, &skb_info)) {
        log_debug("socket__mongo_filter failed to fetch arguments for tail call\n");
        return 0;
    }

    mongo_msg_header mongo_header = {};
    bpf_skb_load_bytes_with_telemetry(skb, skb_info.data_off, (char *)&mongo_header, MONGO_HEADER_LENGTH);
    try_parse_mongo_header(&tup, (const char *)&mongo_header, MONGO_HEADER_LENGTH);
    return 0;
}

/// This function is called by the socket-filter program to decide whether or not we should inspect
/// the contents of a certain packet, in order to avoid the cost of processing packets that are not
/// of interest such as empty ACKs, UDP data or encrypted traffic.
static __always_inline bool mongo_allow_packet(mongo_transaction_t *mongo, struct __sk_buff* skb, skb_info_t *skb_info) {
    // we're only interested in TCP traffic
    if (!(mongo->base.tup.metadata&CONN_TYPE_TCP)) {
        return false;
    }

    // if payload data is empty or if this is an encrypted packet, we only
    // process it if the packet represents a TCP termination
    bool empty_payload = skb_info->data_off == skb->len;
    if (empty_payload) {
        return skb_info->tcp_flags&(TCPHDR_FIN|TCPHDR_RST);
    }

    // Check that we didn't see this tcp segment before so we won't process
    // the same traffic twice
    // Hack to make verifier happy on 4.14.
    conn_tuple_t tup = mongo->base.tup;
    __u32 *last_tcp_seq = bpf_map_lookup_elem(&mongo_last_tcp_seq_per_connection, &tup);
    if (last_tcp_seq != NULL && *last_tcp_seq == skb_info->tcp_seq) {
        log_debug("mongo: already seen this tcp sequence: %lu\n", *last_tcp_seq);
        return false;
    }
    bpf_map_update_with_telemetry(mongo_last_tcp_seq_per_connection, &tup, &skb_info->tcp_seq, BPF_ANY);
    return true;
}

#endif
