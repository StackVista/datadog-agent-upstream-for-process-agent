#ifndef __MONGO_HELPERS_H
#define __MONGO_HELPERS_H

#include "protocols/classification/common.h"
#include "protocols/mongo/defs.h"

/// Adds a request id to the mongo_request_id set
static __always_inline void mongo_handle_request(conn_tuple_t *tup, __s32 request_id) {
    // Track the time we observed this request for latency calculation.
    __u64 timestamp = bpf_ktime_get_ns();
    mongo_key key = {};
    key.tup = *tup;
    key.req_id = request_id;
    bpf_map_update_elem(&mongo_request_timestamps, &key, &timestamp, BPF_ANY);
}

/// @brief Searches for the timestamp the request matching the given response was observed.
/// If the request was observed, it will be removed from the map and the latency will be calculated and enqueued
/// for user-space processing.
/// @param tup Identifier for the connection.
/// @param response_to Value of the response_to header field.
/// @return Timestamp the request identified by tup and response_to was observed, or 0 if it was not observed.
static __always_inline __u64 mongo_have_seen_request(conn_tuple_t *tup, __s32 response_to) {
    mongo_key key = {};
    key.tup = *tup;
    key.req_id = response_to;
    __u64 *timestamp = bpf_map_lookup_elem(&mongo_request_timestamps, &key);
    bpf_map_delete_elem(&mongo_request_timestamps, &key);
    if (timestamp == NULL) {
        return 0;
    }

    return *timestamp;
}

// Checks if the connection identified by tup is a mongo connection.
// Once this has returned true, it will not be called again for traffic on the same connection. 
// Returning false will give us another chance for classification with the next packet.
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

#endif
