#ifndef __MONGO_CLASSIFICATION_H
#define __MONGO_CLASSIFICATION_H

#include "protocols/helpers/big_endian.h"
#include "protocols/mongo/defs.h"
// #include "protocols/mongo/maps.h"
#include "protocols/mongo/types.h"
#include "protocols/classification/usm-context.h"

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

    /*
    if (!is_valid_kafka_request_header(&mongo_header)) {
        return false;
    }

    u32 offset = skb_info->data_off + sizeof(mongo_header_t);
    // Validate client ID
    // Client ID size can be equal to '-1' if the client id is null.
    if (mongo_header.client_id_size > 0) {
        if (!is_valid_client_id(skb, offset, mongo_header.client_id_size)) {
            return false;
        }
        offset += mongo_header.client_id_size;
    } else if (mongo_header.client_id_size < -1) {
        return false;
    }

    return is_kafka_request(&mongo_header, skb, offset);
    */
   return false;
}

#endif
