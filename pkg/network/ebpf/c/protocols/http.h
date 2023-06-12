#ifndef __HTTP_H
#define __HTTP_H

#include "bpf_builtins.h"
#include "bpf_telemetry.h"
#include "tracer.h"
#include "http-types.h"
#include "http-maps.h"
#include "https.h"
#include "events.h"

#include <uapi/linux/ptrace.h>

USM_EVENTS_INIT(http, http_transaction_t, HTTP_BATCH_SIZE);

static __always_inline int http_responding(http_transaction_t *http) {
    return (http != NULL && http->response_status_code != 0);
}

static __always_inline void http_begin_request(http_transaction_t *http, http_method_t method, char *buffer) {
    http->request_method = method;
    http->request_started = bpf_ktime_get_ns();
    http->response_last_seen = 0;
    http->response_status_code = 0;
    bpf_memcpy(&http->request_fragment, buffer, HTTP_BUFFER_SIZE);
    log_debug("http_begin_request: htx=%llx method=%d start=%llx\n", http, http->request_method, http->request_started);
}

static __always_inline void http_begin_response(http_transaction_t *http, const char *buffer) {
    u16 status_code = 0;
    status_code += (buffer[HTTP_STATUS_OFFSET+0]-'0') * 100;
    status_code += (buffer[HTTP_STATUS_OFFSET+1]-'0') * 10;
    status_code += (buffer[HTTP_STATUS_OFFSET+2]-'0') * 1;
    http->response_status_code = status_code;
    log_debug("http_begin_response: htx=%llx status=%d\n", http, status_code);
}

static __always_inline bool http_response_line_end_offset(skb_info_t *skb_info, const char *buffer) {
    // Read the response status_line until we hit a return character up to a maximum of HTTP_RESPONSE_STATUS_LINE_MAX_SIZE
    // and set the offset.
    // HTTP/1.1 200 OK
    // _______________^
    __u8 return_found = 0;
#pragma unroll
    for (int i = 0; i < HTTP_RESPONSE_STATUS_LINE_MAX_SIZE; i++)
    {
        // check to see if we've reached the end of the status line, signified by a new line (13 10 - unicode) U+000D U+000A
        if (!return_found && buffer[i] == '\n')
        {
            skb_info->http_header_off = skb_info->data_off + i + 1;
            return 1;
        }
    }

    return 0;
}
static __always_inline int is_x_trace_id_header(char *match_buffer, trace_match_t *trace_match)
{
    // set the local position to be used as the "starting" point.
    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 'x') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == '-') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 't') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 'r') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 'a') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 'c') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 'e') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == '-') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 'i') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == 'd') { trace_match->matches++; trace_match->position++; }
    else { return 0; }
    trace_match->position++;

    if (trace_match->position > HTTP_TRACING_ID_HEADER_SIZE) { return -1; }
    if (match_buffer[trace_match->position] == ':') { trace_match->matches++; trace_match->position++; }
    else { return 0; }

    // everything matched, this is the x-trace-id header
    return 1;
}
//
static __always_inline trace_header_match_t find_trace_id_header(char *match_buffer, trace_match_t *trace_match)
{
    __u8 skip_current_header = 0;
    do {
        if (skip_current_header && match_buffer[trace_match->position] == '\n')
        {
            // move to the character after the new-line
            trace_match->position++;
            trace_match->matches = 0;
            continue;
        }

        int is_trace_id_header = is_x_trace_id_header(match_buffer, trace_match);
        // not a match for the trace header, skip this header and continue traversing the buffer
        if(is_trace_id_header == 0)
        {
            // skip this header; ie. read until we reach a new-line / end of buffer
            skip_current_header = 1;
            trace_match->matches = 0;
            continue;
        }
        else if(is_trace_id_header == 1)
        {  // trace header match
            return FULL_MATCH;
        }
        else if(is_trace_id_header == -1)
        { // end of the buffer
            if(trace_match->matches > 0)
            {
                return PARTIAL_MATCH;
            }
            else
            {
                return NO_MATCH;
            }
        }

        // move to the next position
        trace_match->position++;
    }
    while (trace_match->position < HTTP_TRACING_ID_HEADER_SIZE);

    return NO_MATCH;
}

static __always_inline bool http_read_response_headers(http_transaction_t *http, struct __sk_buff* skb, skb_info_t *skb_info) {

    // load chunks of 49 chars and try to find x-trace-id header in the format -> x-trace-id: 16266295-c3fa-4fae-994c-b35f1d02c1c8
    char trace_buffer[HTTP_TRACING_ID_HEADER_SIZE];
    bpf_memset(trace_buffer, 0, sizeof(HTTP_TRACING_ID_HEADER_SIZE));

    if (skb->len - skb_info->http_header_off < HTTP_TRACING_ID_HEADER_SIZE)
    {
        return false;
    }

    u64 offset = (u64)skb_info->http_header_off;
    const u32 len = HTTP_HEADER_LIMIT < (skb->len - (u32)offset) ? (u32)offset + HTTP_HEADER_LIMIT : skb->len;

    trace_match_t trace_match;
    bpf_memset(&trace_match, 0, sizeof(trace_match));
    trace_match.matches = 0;
    trace_match.position = 0;

// HTTP_HEADER_LIMIT = 8196
// HTTP_TRACING_ID_HEADER_SIZE = 49
#pragma unroll (HTTP_HEADER_LIMIT / HTTP_TRACING_ID_HEADER_SIZE)
    for (int i = 0; i < len; i++)
    {
        if (offset + HTTP_TRACING_ID_HEADER_SIZE - 1 >= len) { break; }
//
        bpf_skb_load_bytes(skb, offset, (char *)trace_buffer, HTTP_TRACING_ID_HEADER_SIZE);
//
//        // try to find the trace id header, result can be:
//        // full match -> We have the header, set the connection tracing_id
//        // partial match -> We have a partial match, increase the offset with trace_match->matches and load another chunk.
//        //                  This next chunk should be a complete match on the header + uuid.
//        // no match -> no match was found in the current chunk. Load the next HTTP_TRACING_ID_HEADER_SIZE chunk.
        trace_header_match_t match_result = find_trace_id_header((char *)trace_buffer, &trace_match);
        switch(match_result)
        {
            case FULL_MATCH:
                log_debug("http_x_trace_id_header_in_response: trace_buffer=%s\n", trace_buffer);
//
//                bpf_memcpy(&http->tracing_id, trace_buffer, HTTP_BUFFER_SIZE);
//
                break;
            case PARTIAL_MATCH:
                // move the offset to the start of the match and load the next chunk. It should be a complete match on
                // the header + uuid.
                offset += (trace_match.position - trace_match.matches);
                trace_match.matches = 0;
                trace_match.position = 0;
            case NO_MATCH:
               // reset everything and increment the offset to load the next chunk.
                trace_match.matches = 0;
                trace_match.position = 0;
                offset += HTTP_TRACING_ID_HEADER_SIZE;
        }

    }

    return true;
}

static __always_inline void http_parse_data(char const *p, http_packet_t *packet_type, http_method_t *method) {
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
        *packet_type = HTTP_RESPONSE;
    } else if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3]  == ' ') && (p[4] == '/')) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_GET;
    } else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4]  == ' ') && (p[5] == '/')) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_POST;
    } else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3]  == ' ') && (p[4] == '/')) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_PUT;
    } else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E') && (p[6]  == ' ') && (p[7] == '/')) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_DELETE;
    } else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4]  == ' ') && (p[5] == '/')) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_HEAD;
    } else if ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S') && (p[7]  == ' ') && ((p[8] == '/') || (p[8] == '*'))) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_OPTIONS;
    } else if ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H') && (p[5]  == ' ') && (p[6] == '/')) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_PATCH;
    }
}

static __always_inline bool http_seen_before(http_transaction_t *http, skb_info_t *skb_info) {
    if (!skb_info || !skb_info->tcp_seq) {
        return false;
    }

    // check if we've seen this TCP segment before. this can happen in the
    // context of localhost traffic where the same TCP segment can be seen
    // multiple times coming in and out from different interfaces
    return http->tcp_seq == skb_info->tcp_seq;
}

static __always_inline void http_update_seen_before(http_transaction_t *http, skb_info_t *skb_info) {
    if (!skb_info || !skb_info->tcp_seq) {
        return;
    }

    log_debug("http_update_seen_before: htx=%llx old_seq=%d seq=%d\n", http, http->tcp_seq, skb_info->tcp_seq);
    http->tcp_seq = skb_info->tcp_seq;
}


static __always_inline http_transaction_t *http_fetch_state(http_transaction_t *http, http_packet_t packet_type) {
    if (packet_type == HTTP_PACKET_UNKNOWN) {
        return bpf_map_lookup_elem(&http_in_flight, &http->tup);
    }

    // We detected either a request or a response
    // In this case we initialize (or fetch) state associated to this tuple
    bpf_map_update_with_telemetry(http_in_flight, &http->tup, http, BPF_NOEXIST);
    return bpf_map_lookup_elem(&http_in_flight, &http->tup);
}

static __always_inline bool http_should_flush_previous_state(http_transaction_t *http, http_packet_t packet_type) {
    return (packet_type == HTTP_REQUEST && http->request_started) ||
        (packet_type == HTTP_RESPONSE && http->response_status_code);
}

static __always_inline bool http_closed(http_transaction_t *http, skb_info_t *skb_info, u16 pre_norm_src_port) {
    return (skb_info && skb_info->tcp_flags&(TCPHDR_FIN|TCPHDR_RST) &&
            // This is done to avoid double flushing the same
            // `http_transaction_t` to userspace.  In the context of a regular
            // TCP teardown, the FIN flag will be seen in "both ways", like:
            //
            // server -> FIN -> client
            // server <- FIN <- client
            //
            // Since we can't make any assumptions about the ordering of these
            // events and there are no synchronization primitives available to
            // us, the way we solve it is by storing the non-normalized src port
            // when we start tracking a HTTP transaction and ensuring that only the
            // FIN flag seen in the same direction will trigger the flushing event.
            http->owned_by_src_port == pre_norm_src_port);
}

static __always_inline int http_process(http_transaction_t *http_stack, skb_info_t *skb_info, __u64 tags) {
    char *buffer = (char *)http_stack->request_fragment;
    http_packet_t packet_type = HTTP_PACKET_UNKNOWN;
    http_method_t method = HTTP_METHOD_UNKNOWN;
    http_parse_data(buffer, &packet_type, &method);

    http_transaction_t *http = http_fetch_state(http_stack, packet_type);
    if (!http || http_seen_before(http, skb_info)) {
        return 0;
    }

    if (http_should_flush_previous_state(http, packet_type)) {
        http_batch_enqueue(http);
        bpf_memcpy(http, http_stack, sizeof(http_transaction_t));
    }

    log_debug("http_process: type=%d method=%d\n", packet_type, method);
    if (packet_type == HTTP_REQUEST) {
        http_begin_request(http, method, buffer);
        http_update_seen_before(http, skb_info);
    } else if (packet_type == HTTP_RESPONSE) {
        http_begin_response(http, buffer);
        http_update_seen_before(http, skb_info);
        http_response_line_end_offset(skb_info, buffer);
    }

    http->tags |= tags;

    // STS Addition: Only set the response time when there is actual data flowing, to
    // avoid a delayed connection close with no data (empty FIN packet) falsely increases the latency.
    if (http_responding(http) && skb_info && skb_info->data_length != 0) {
        http->response_last_seen = bpf_ktime_get_ns();
    }

    if (http_closed(http, skb_info, http_stack->owned_by_src_port)) {
        http_batch_enqueue(http);
        bpf_map_delete_elem(&http_in_flight, &http_stack->tup);
    }

    return 0;
}

// this function is called by the socket-filter program to decide whether or not we should inspect
// the contents of a certain packet, in order to avoid the cost of processing packets that are not
// of interest such as empty ACKs, UDP data or encrypted traffic.
static __always_inline bool http_allow_packet(http_transaction_t *http, struct __sk_buff* skb, skb_info_t *skb_info) {
    // we're only interested in TCP traffic
    if (!(http->tup.metadata&CONN_TYPE_TCP)) {
        return false;
    }

    // if payload data is empty or if this is an encrypted packet, we only
    // process it if the packet represents a TCP termination
    bool empty_payload = skb_info->data_off == skb->len;
    if (empty_payload || http->tup.sport == HTTPS_PORT || http->tup.dport == HTTPS_PORT) {
        return skb_info->tcp_flags&(TCPHDR_FIN|TCPHDR_RST);
    }

    return true;
}


#endif
