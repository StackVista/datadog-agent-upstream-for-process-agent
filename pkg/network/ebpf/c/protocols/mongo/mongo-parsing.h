#ifndef __MONGO_PARSING
#define __MONGO_PARSING

#include "bpf_builtins.h"
#include "bpf_telemetry.h"
#include "protocols/mongo/defs.h"
#include "protocols/mongo/types.h"
#include "protocols/mongo/parsing-maps.h"
#include "protocols/mongo/usm-events.h"


// Entry point for mongo 
static __always_inline bool mongo_process(mongo_transaction_t *mongo_transaction, struct __sk_buff* skb, __u32 offset);

// The actual data extraction and pushing to user-space. For TLS, we come here from uprobe__mongo_process,
// for unencrypted traffic, we come here from socket__mongo_filter via mongo_process.
static __always_inline bool mongo_process_header(mongo_transaction_t *mongo_transaction, mongo_header_t *mongo_header);

// This is our entry point for MongoDB over TLS traffic.
// The TLS dispatcher gives a different context from the unencrypted one, so we need to do a little
// dance here get to the mongo header.
SEC("uprobe/mongo_process")
int uprobe__mongo_process(struct pt_regs *ctx) {
    const __u32 zero = 0;
    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (args == NULL) {
        return 0;
    }

    mongo_transaction_t *mongo_transaction = bpf_map_lookup_elem(&mongo_heap, &zero);
    if (mongo_transaction == NULL) {
        return 0;
    }

    bpf_memset(mongo_transaction, 0, sizeof(mongo_transaction_t));
    bpf_memcpy(&mongo_transaction->base.tup, &args->tup, sizeof(conn_tuple_t));
    normalize_tuple(&mongo_transaction->base.tup);

    mongo_header_t mongo_header;
    bpf_probe_read_user_with_telemetry(&mongo_header, sizeof(mongo_header_t), args->buffer_ptr); 
    mongo_process_header(mongo_transaction, &mongo_header);
  
    return 0;
}

// Don't be mislead by the name of this function or by the fact that it is in the socket section.
// This will only be called from the dispatcher for packets on connections that have already been
// identified as mongo connections. This is for unencrypted traffic only, for TLS traffic, see
// the uprobe__mongo_process function above.
SEC("socket/mongo_filter")
int socket__mongo_filter(struct __sk_buff* skb) {
    log_debug("socket__mongo_filter: start\n");
    const u32 zero = 0;
    skb_info_t skb_info;

    mongo_transaction_t *mongo = bpf_map_lookup_elem(&mongo_heap, &zero);
    if (mongo == NULL) {
        log_debug("socket__mongo_filter: mongo_transaction state is NULL\n");
        return 0;
    }
    bpf_memset(mongo, 0, sizeof(mongo_transaction_t));

    if (!fetch_dispatching_arguments(&mongo->base.tup, &skb_info)) {
        log_debug("socket__mongo_filter failed to fetch arguments for tail call\n");
        return 0;
    }
    // TODO: Move to mongo_process
    normalize_tuple(&mongo->base.tup);

    (void)mongo_process(mongo, skb, skb_info.data_off);
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
