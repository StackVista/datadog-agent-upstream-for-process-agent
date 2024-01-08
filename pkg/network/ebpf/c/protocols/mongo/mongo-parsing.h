#ifndef __MONGO_PARSING
#define __MONGO_PARSING

#include "bpf_builtins.h"
#include "bpf_telemetry.h"
#include "protocols/mongo/types.h"
#include "protocols/mongo/parsing-maps.h"
#include "protocols/mongo/usm-events.h"

// forward declaration
static __always_inline bool mongo_allow_packet(mongo_transaction_t *mongo, struct __sk_buff* skb, skb_info_t *skb_info);
static __always_inline bool mongo_process(mongo_transaction_t *mongo_transaction, struct __sk_buff* skb, __u32 offset);

SEC("socket/mongo_filter")
int socket__mongo_filter(struct __sk_buff* skb) {
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

    if (!mongo_allow_packet(mongo, skb, &skb_info)) {
        return 0;
    }
    normalize_tuple(&mongo->base.tup);

    (void)mongo_process(mongo, skb, skb_info.data_off);
    return 0;
}

static __always_inline bool mongo_process(mongo_transaction_t *mongo_transaction, struct __sk_buff* skb, __u32 offset) {
    /*
        We perform mongo request validation as we can get mongo traffic that is not relevant for parsing (unsupported requests, responses, etc)
    */

    mongo_header_t mongo_header;
    bpf_memset(&mongo_header, 0, sizeof(mongo_header));
    bpf_skb_load_bytes_with_telemetry(skb, offset, (char *)&mongo_header, sizeof(mongo_header));
    mongo_header.message_length = bpf_ntohl(mongo_header.message_length);
    mongo_header.op_code = bpf_ntohs(mongo_header.op_code);
    mongo_header.request_id = bpf_ntohs(mongo_header.request_id);
    mongo_header.response_to = bpf_ntohl(mongo_header.response_to);

    log_debug("mongo: mongo_header.op_code: %d\n", mongo_header.op_code);
    log_debug("mongo: mongo_header.request_id: %d\n", mongo_header.request_id);
    log_debug("mongo: mongo_header.response_to: %d\n", mongo_header.response_to);

    if (!is_valid_mongo_request_header(&mongo_header)) {
        return false;
    }

    mongo_transaction->base.mongo_request_id = mongo_header.request_id;
    offset += sizeof(mongo_header_t);

    mongo_batch_enqueue(&mongo_transaction->base);
    return true;
}

// this function is called by the socket-filter program to decide whether or not we should inspect
// the contents of a certain packet, in order to avoid the cost of processing packets that are not
// of interest such as empty ACKs, UDP data or encrypted traffic.
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
    log_debug("mongo: Current tcp sequence: %lu\n", skb_info->tcp_seq);
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
