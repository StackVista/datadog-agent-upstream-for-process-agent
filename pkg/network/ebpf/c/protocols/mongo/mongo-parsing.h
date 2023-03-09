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

#endif
