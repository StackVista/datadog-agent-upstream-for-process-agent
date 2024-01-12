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
static __always_inline bool mongo_process_header(mongo_transaction_t *mongo_transaction, mongo_header_t *mongo_header);

SEC("uprobe/mongo_process")
int uprobe__mongo_process(struct pt_regs *ctx) {
    log_debug("mongo: uprobe__mongo_process: start\n");
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

    mongo_process_header(mongo_transaction, (mongo_header_t *)args->buffer_ptr);

    /*
    if (sizeof(mongo_header_t) > args->len) {
        return 0;
    }
    mongo_header_t mongo_header;
    bpf_memcpy(&mongo_header, args->buffer_ptr, sizeof(mongo_header_t));

    // buffer_ptr is not a sk buffer but mongo_process only looks for the payload anyway
    mongo_process_header(mongo_transaction, mongo_header);
    http_batch_flush(ctx);
    */
   
    return 0;
}

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

    if (!mongo_allow_packet(mongo, skb, &skb_info)) {
        log_debug("socket__mongo_filter: mongo_allow_packet returned false\n");
        return 0;
    }
    normalize_tuple(&mongo->base.tup);

    (void)mongo_process(mongo, skb, skb_info.data_off);
    return 0;
}

static __always_inline bool is_valid_mongo_request_header (mongo_header_t *header) {
    // TODO: Validate at least request/response id and OP_CODE plausibility.
    return true;
}

static __always_inline bool mongo_process(mongo_transaction_t *mongo_transaction, struct __sk_buff* skb, __u32 offset) {
    mongo_header_t mongo_header;
    bpf_memset(&mongo_header, 0, sizeof(mongo_header));
    bpf_skb_load_bytes_with_telemetry(skb, offset, (char *)&mongo_header, sizeof(mongo_header));
    mongo_process_header(mongo_transaction, &mongo_header);

    return true;
}

static __always_inline bool mongo_process_header(mongo_transaction_t *mongo_transaction, mongo_header_t *mongo_header) {
    // STS/JGT: The bswap dance is required to go from Mongos little-endian to network byte to host byte order.
    log_debug("mongo: mongo_header.op_code: %u\n", bpf_ntohl(__builtin_bswap32(mongo_header->op_code)));
    log_debug("mongo: mongo_header.request_id: %u\n", bpf_ntohl(__builtin_bswap32(mongo_header->request_id)));
    log_debug("mongo: mongo_header.response_to: %u\n", bpf_ntohl(__builtin_bswap32(mongo_header->response_to)));

    if (!is_valid_mongo_request_header(mongo_header)) {
        return false;
    }

    mongo_transaction->base.mongo_request_id = mongo_header->request_id;
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
