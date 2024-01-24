#ifndef __MONGO_HELPERS
#define __MONGO_HELPERS

#include "protocols/mongo/maps.h"
#include "protocols/mongo/usm-events.h"

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
/// @param tup Identifier for the connection. Must be a normalized tuple for the mathing to work.
/// @param response_to Value of the response_to header field.
/// @return Timestamp the request identified by tup and response_to was observed, or 0 if it was not observed.
static __always_inline __u64 mongo_try_match_request(conn_tuple_t *tup, __s32 response_to) {
    mongo_key key = {};
    key.tup = *tup;
    key.req_id = response_to;
    __u64 *timestamp = bpf_map_lookup_elem(&mongo_request_timestamps, &key);
    bpf_map_delete_elem(&mongo_request_timestamps, &key);
    if (timestamp == NULL) {
        return 0;
    }

    // Calculate the latency and enqueue it for user-space processing.
    __u64 now = bpf_ktime_get_ns();
    __u64 latency = now - *timestamp;
    mongo_transaction_batch_entry_t entry = {};
    entry.tup = *tup;
    entry.mongo_latency_ns = latency;
    mongo_batch_enqueue(&entry);
    return *timestamp;
}

// Validates and parse `buf` as a mongo header and records its request id and observation
// timestamp for latency calculation. Return true if the header is valid, false otherwise.
// While this should never fail to identify a valid header, there is a high chance of false
// positives. This is because the header is very simple and the only field we can validate
// is the op_code.
static __always_inline bool try_parse_mongo_header(conn_tuple_t *raw_tup, const char *buf, __u32 size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, size, MONGO_HEADER_LENGTH);

    // For matching, we need a consistent tuple format.
    // Make a copy as we do not know what the caller will do with the tuple.
    conn_tuple_t tup_copy = *raw_tup;
    conn_tuple_t *tup = &tup_copy;
    normalize_tuple(tup);

    mongo_msg_header header = *((mongo_msg_header*)buf);

    // Header is little-endian on thr wire, convert to host byte order.
    header.message_length = bpf_ntohl(__builtin_bswap32(header.message_length));
    header.request_id = bpf_ntohl(__builtin_bswap32(header.request_id));
    header.response_to = bpf_ntohl(__builtin_bswap32(header.response_to));
    header.op_code = bpf_ntohl(__builtin_bswap32(header.op_code));

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
        return mongo_try_match_request(tup, header.response_to);
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
        return mongo_try_match_request(tup, header.response_to);
    }

    return false;
}

// Checks if the connection identified by tup is a mongo connection.
// Once this has returned true, it will not be called again for traffic on the same connection. 
// Returning false will give us another chance for classification with the next packet.
static __always_inline bool is_mongo(conn_tuple_t *tup, const char *buf, __u32 size) {
    __u32 tries = 0;
    __u32 *tries_ptr = bpf_map_lookup_elem(&mongo_connection_classification_tries, tup);
    if (tries_ptr != NULL) {
        tries = *tries_ptr;
    }

    if (tries >= MONGO_MAX_CLASSIFICATION_TRIES) {
        // We've tried to classify this connection too many times, give up.
        // This approach is not necessarily more performant then just trying to parse the header
        // every time, but we want to avoid false positives.
        return false;
    }

    tries++;
    bpf_map_update_elem(&mongo_connection_classification_tries, tup, &tries, BPF_ANY);

    return try_parse_mongo_header(tup, buf, size);
}

#endif