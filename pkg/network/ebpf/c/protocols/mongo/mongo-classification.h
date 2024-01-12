#ifndef __MONGO_CLASSIFICATION_H
#define __MONGO_CLASSIFICATION_H

#include "protocols/helpers/big_endian.h"
#include "protocols/mongo/defs.h"
// #include "protocols/mongo/maps.h"
#include "protocols/mongo/types.h"
#include "protocols/classification/usm-context.h"

/*
static __always_inline void mongo_handle_request(conn_tuple_t *tup, __s32 request_id) {
    // mongo_request_id acts as a set, and we only check for existence in that set.
    // Thus, the val = true is just a dummy value, as we ignore the value.
    const bool val = true;
    mongo_key key = {};
    key.tup = *tup;
    key.req_id = request_id;
    bpf_map_update_elem(&mongo_request_id, &key, &val, BPF_ANY);
}

static __always_inline bool mongo_have_seen_request(conn_tuple_t *tup, __s32 response_to) {
    mongo_key key = {};
    key.tup = *tup;
    key.req_id = response_to;
    void *exists = bpf_map_lookup_elem(&mongo_request_id, &key);
    bpf_map_delete_elem(&mongo_request_id, &key);
    return exists != NULL;
}

// Checks if the given buffer represents a mongo request or a response.
static __always_inline bool is_mongo(conn_tuple_t *tup, const char *buf, __u32 size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, size, MONGO_HEADER_LENGTH);

    mongo_msg_header header = *((mongo_msg_header*)buf);

    // The message length should contain the size of headers
    if (header.message_length < MONGO_HEADER_LENGTH) {
        return false;
    }

    if (header.request_id < 0) {
        return false;
    }

    switch (header.op_code) {
    case MONGO_OP_UPDATE:
    case MONGO_OP_INSERT:
    case MONGO_OP_DELETE:
        // If the response_to is not 0, then it is not a valid mongo request by the RFC.
        return header.response_to == 0;
    case MONGO_OP_REPLY:
        // If the message is a reply, make sure we've seen the request of the response.
        // If will eliminate false positives.
        return mongo_have_seen_request(tup, header.response_to);
    case MONGO_OP_QUERY:
    case MONGO_OP_GET_MORE:
        if (header.response_to == 0) {
            mongo_handle_request(tup, header.request_id);
            return true;
        }
        return false;
    case MONGO_OP_COMPRESSED:
    case MONGO_OP_MSG:
        // If the response_to is not 0, then it is not a valid mongo request by the RFC.
        if (header.response_to == 0) {
            mongo_handle_request(tup, header.request_id);
            return true;
        }
        return mongo_have_seen_request(tup, header.response_to);
    }

    return false;
}

// Checks if the packet represents a mongo request.
static __always_inline bool is_mongo(struct __sk_buff *skb, skb_info_t *skb_info, const char* buf, __u32 buf_size, conn_tuple_t *skb_tup) {
    log_debug("Calling into is_mongo with skb argument");
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, MONGO_MIN_LENGTH);

    const mongo_header_t *header_view = (mongo_header_t *)buf;
    mongo_header_t mongo_header;
    bpf_memset(&mongo_header, 0, sizeof(mongo_header));
    mongo_header.message_length = bpf_ntohl(header_view->message_length);
    mongo_header.op_code = bpf_ntohs(header_view->op_code);
    mongo_header.request_id = bpf_ntohs(header_view->request_id);
    mongo_header.response_to = bpf_ntohl(header_view->response_to);

    // Check if source or target port match the mongo default port.
    __u16 mongo_default_port = 27017;
    if ((skb_tup->sport == mongo_default_port) || (skb_tup->dport == mongo_default_port)) {
        log_debug("Src port: %d, Dst port: %d", skb_tup->sport, skb_tup->dport);
        return true;
    }

   return false;
}
*/

#endif
