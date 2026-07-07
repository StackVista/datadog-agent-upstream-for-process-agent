#ifndef __HTTP_H
#define __HTTP_H

#include "protocols/http/http_tracing.h"

#include "bpf_builtins.h"
#include "bpf_telemetry.h"

#include "protocols/sockfd.h"

#include "protocols/classification/common.h"

#include "protocols/http/types.h"
#include "protocols/http/maps.h"
#include "protocols/http/usm-events.h"
#include "protocols/tls/https.h"

static __always_inline int http_responding(http_transaction_t *http) {
    return (http != NULL && http->response_status_code != 0);
}

static __always_inline void http_begin_request(http_transaction_t *http, http_method_t method, char *buffer) {
    http->request_method = method;
    http->request_started = bpf_ktime_get_ns();
    http->response_last_seen = 0;
    http->response_status_code = 0;
    bpf_memcpy(&http->request_fragment, buffer, HTTP_BUFFER_SIZE);
    log_debug("http_begin_request: htx=%p method=%d start=%llx", http, http->request_method, http->request_started);
}

static __always_inline void http_begin_response(http_transaction_t *http, const char *buffer) {
    u16 status_code = 0;
    status_code += (buffer[HTTP_STATUS_OFFSET+0]-'0') * 100;
    status_code += (buffer[HTTP_STATUS_OFFSET+1]-'0') * 10;
    status_code += (buffer[HTTP_STATUS_OFFSET+2]-'0') * 1;
    http->response_status_code = status_code;
    log_debug("http_begin_response: htx=%p status=%d", http, status_code);
}

static __always_inline void http_batch_enqueue_wrapper(conn_tuple_t *tuple, http_transaction_t *http) {
    u32 zero = 0;
    http_event_t *event = bpf_map_lookup_elem(&http_scratch_buffer, &zero);
    if (!event) {
        return;
    }

    bpf_memcpy(&event->tuple, tuple, sizeof(conn_tuple_t));
    bpf_memcpy(&event->http, http, sizeof(http_transaction_t));
    http_batch_enqueue(event);
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
    } else if ((p[0] == 'T') && (p[1] == 'R') && (p[2] == 'A') && (p[3] == 'C') && (p[4] == 'E') && (p[5]  == ' ') && (p[6] == '/')) {
        *packet_type = HTTP_REQUEST;
        *method = HTTP_TRACE;
    }
}

static __always_inline bool http_closed(skb_info_t *skb_info) {
    return (skb_info && skb_info->tcp_flags&(TCPHDR_FIN|TCPHDR_RST));
}

// this is merely added here to improve readibility of code.
// HTTP monitoring code is executed in two "contexts":
// * via a socket filter program, which is used for monitoring plain traffic;
// * via a uprobe-based programs, for the purposes of tracing encrypted traffic (SSL, Go TLS, Java TLS etc);
// When code is executed from uprobes, skb_info is null[1].
//
// [1] There is one notable exception that happens when we process uprobes
// triggering the termination of connections. In that particular context we
// "inject" a special skb_info that has the tcp_flags field set to `TCPHDR_FIN`.
static __always_inline bool is_uprobe_context(skb_info_t *skb_info) {
    return skb_info == NULL || (skb_info->data_end == 0 && http_closed(skb_info));
}

// The purpose of http_seen_before is to is to avoid re-processing certain TCP segments.
// We only care about 3 types of segments:
// * A segment with the beginning of a request (packet_type == HTTP_REQUEST);
// * A segment with the beginning of a response (packet_type == HTTP_RESPONSE);
// * A segment with a (FIN|RST) flag set;
static __always_inline bool http_seen_before(http_transaction_t *http, skb_info_t *skb_info, http_packet_t packet_type) {
    if (is_uprobe_context(skb_info) && !http_closed(skb_info)) {
        // The purpose of setting tcp_seq = 0 in the context of uprobe tracing
        // is innocuous for the most part (as this field will almost aways be 0)
        // The only reason we do this here is to *minimize* the chance of a race
        // condition that happens sometimes in the context of uprobe-based tracing:
        //
        // 1) handle_request for c1 (uprobe)
        // 2) socket filter triggers termination code for c1 (server -> FIN -> client)
        // 3) handle_response for c1 (uprobe)
        // 4) socket filter triggers termination code for c1 (client -> FIN -> server)
        //
        // The problem is that 2) and 3) might happen in parallel, and 2) may
        // delete the the eBPF data *before* 4) executes and flushes the data
        // with both request and response information to userspace.
        //
        // Since we check if (skb_info->tcp_seq == HTTP_TERMINATING) evaluates
        // to true before flushing and deleting the eBPF map data, setting it to
        // 0 here gives a chance for the late response to "cancel" the map
        // deletion.
        
        // [STS] This code was introduced to fix a race condition between uprobes 
        // and socket filters (https://github.com/DataDog/datadog-agent/pull/20829). 
        // This is just a mitigation not a real fix, right now we prefer to keep our
        // version since we've never seen this race condition but in the future
        // we could face the same issue. 
        // One real solution would be to use TC programs instead of socket filters, 
        // in this way we will be always sure that the TC programs are executed before the uprobe.
                
        // http->tcp_seq = 0;
        return false;
    }

    if (packet_type != HTTP_REQUEST && packet_type != HTTP_RESPONSE && !http_closed(skb_info)) {
        return false;
    }

    if (http_closed(skb_info)) {
        // Override sequence number with a special sentinel value
        // This is done so we consider
        // Server -> FIN(sequence=x) -> Client
        // And
        // Client -> FIN(sequence=y) -> Server
        // To be the same thing in order to avoid flushing the same transaction twice to userspace
        skb_info->tcp_seq = HTTP_TERMINATING;
    }

    if (http->tcp_seq == skb_info->tcp_seq) {
        return true;
    }

    // [STS] We set the `http->tcp_seq` into `http_update_seen_before` so we don't need it here.
    // todo!: Commenting this causes the the issue described above, we are flushing the same transaction twice to userspace.
    // http->tcp_seq = skb_info->tcp_seq;
    return false;
}

static __always_inline void http_update_seen_before(http_transaction_t *http, skb_info_t *skb_info) {
    if (!skb_info || !skb_info->tcp_seq) {
        return;
    }

    log_debug("http_update_seen_before: htx=%p old_seq=%d seq=%d\n", http, http->tcp_seq, skb_info->tcp_seq);
    http->tcp_seq = skb_info->tcp_seq;
}

/** Global empty value to assist with initialization of the map items.
*/
static http_transaction_t init_zero;

static __always_inline http_transaction_t *http_fetch_state(conn_tuple_t *tuple, http_packet_t packet_type) {
    if (packet_type == HTTP_PACKET_UNKNOWN) {
        // We should never recreate a new transaction for an unknown packet type.
        // if the connection is not there it means we are in a websocket connection or we have already closed the TCP connection
        return bpf_map_lookup_elem(&http_in_flight, tuple);
    }

    // We detected either a request or a response
    // In this case we initialize (or fetch) state associated to this tuple
    //
    // We skip EEXIST because of the use of BPF_NOEXIST flag. Emitting telemetry for EEXIST here spams metrics
    // and do not provide any useful signal since the key is expected to be present sometimes.
    //
    // EBUSY can be returned if a program tries to access an already held bucket lock
    // https://elixir.bootlin.com/linux/latest/source/kernel/bpf/hashtab.c#L164
    // Before kernel version 6.7 it was possible for a program to get interrupted before disabling
    // interrupts for acquring the bucket spinlock but after marking a bucket as busy.
    // https://github.com/torvalds/linux/commit/d35381aa73f7e1e8b25f3ed5283287a64d9ddff5
    // As such a program running from an irq context would falsely see a bucket as busy in certain cases
    // as explained in the linked commit message.
    //
    // Since http_in_flight is shared between programs running in different contexts, it gets effected by the
    // above scenario.
    // However the EBUSY error does not carry any signal for us since this is caused by a kernel bug.
    bpf_map_update_with_telemetry(http_in_flight, tuple, &init_zero, BPF_NOEXIST, -EEXIST, -EBUSY);

    return bpf_map_lookup_elem(&http_in_flight, tuple);
}



// Returns true if the given http transaction should be flushed to the user mode.
// We flush a transaction if:
//   1. We got a new request (packet_type == HTTP_REQUEST) and previously (in the given transaction) we had either a
//      request (http->request_started != 0) or a response (http->response_status_code). This is equivalent to flush
//      a transaction if we have a new request, and the given transaction is not clean.
//   2. We got a new response (packet_type == HTTP_RESPONSE) and the given transaction already contains a response.
//      It means we missed a request.
static __always_inline bool http_should_flush_previous_state(http_transaction_t *http, http_packet_t packet_type) {
    return (packet_type == HTTP_REQUEST && (http->request_started || http->response_status_code)) ||
        (packet_type == HTTP_RESPONSE && http->response_status_code);
}

// http_process is responsible for parsing traffic and emitting events
// representing HTTP transactions.
static __always_inline void http_process(http_classification_t *http_class, skb_info_t *skb_info, __u64 tags) {
    char *buffer = (char *)http_class->request_fragment;
    // bpf_printk("[http_process]: type=%d, method=%d, trace_id: %s", http_class->packet_type, http_class->method, http_class->tracing_id);

    // We could have several packets here:
    // 1. HTTP_REQUEST
    // 2. HTTP_RESPONSE
    // 3. HTTP_PACKET_UNKNOWN -> TCP packet with FIN or RST flag set
    // 4. HTTP_PACKET_UNKNOWN -> TCP keep-alive packet
    // 5. HTTP_PACKET_UNKNOWN -> HTTP payload that is part of a fragmented response (it seems we ignore the case of a fragmented request)
    // 6. HTTP_PACKET_UNKNOWN -> Websocket frames over HTTP
    http_transaction_t *http = http_fetch_state(&http_class->tuple, http_class->packet_type);
    if (!http || http_seen_before(http, skb_info, http_class->packet_type)) {
        return;
    }

    // We don't want to flush as soon as we see the response because this could be fragmented on different TCP packets.
    // This is why we wait for the next request/response.
    if (http_should_flush_previous_state(http, http_class->packet_type)) {
        http_batch_enqueue_wrapper(&http_class->tuple, http);
        // Clear the transaction. Data about the transaction is filled in after this.
        bpf_memset(http, 0, sizeof(http_transaction_t));
    }

    log_debug("http_process: type=%d method=%d", http_class->packet_type, http_class->method);

    if (http_class->packet_type == HTTP_REQUEST) {
        http_begin_request(http, http_class->method, buffer);
        http_update_seen_before(http, skb_info);
        bpf_memcpy(&http->request_tracing_id, &http_class->tracing_id, HTTP_TRACING_ID_SIZE);
        http->request_parse_result = http_class->parse_result;
    } else if (http_class->packet_type == HTTP_RESPONSE) {
        http_begin_response(http, buffer);
        http_update_seen_before(http, skb_info);
        bpf_memcpy(&http->response_tracing_id, &http_class->tracing_id, HTTP_TRACING_ID_SIZE);
        http->response_parse_result = http_class->parse_result;
        // Special handling for websockets
        // we know that after this packet we will never receive other HTTP traffic on this connection and so 
        // we flush it and we remove it from the in-flight map.
        if(http->response_status_code == WEBSOCKET_STATUS_CODE){
            http->tags |= tags;
            http->response_last_seen = bpf_ktime_get_ns();
            http_batch_enqueue_wrapper(&http_class->tuple, http);
            bpf_map_delete_elem(&http_in_flight, &http_class->tuple);
            return;
        }
    }

    http->tags |= tags;

    // The HTTP response could be fragmented across multiple TCP packets so we want to update
    // the response_last_seen field only in this case.
    // Here we could have:
    // 1. HTTP_REQUEST -> we don't update because `http_responding(http)` is false
    // 2. HTTP_RESPONSE -> we update it
    // 3. TCP packet with FIN or RST flag set -> we don't update because it has no payload
    // 4. TCP keep-alive packet -> we don't update because it has no payload
    // 5. HTTP payload that is part of a fragmented response -> we update it
    // No websocket traffic should arrive here.
    // This is to prevent things such as keep-alives adding up to the transaction latency
    if (((skb_info && !is_payload_empty(skb_info)) || !skb_info) && http_responding(http)) {
        http->response_last_seen = bpf_ktime_get_ns();
    }
    
    // [STS] Part of the race condition work (https://github.com/DataDog/datadog-agent/pull/20829)
    // See the comment above for more details.

    // if (http->tcp_seq == HTTP_TERMINATING) {
    //     http_batch_enqueue_wrapper(&http_class->tuple, http);
    //     // Check a second time to minimize the chance of accidentally deleting a
    //     // map entry if there is a race with a late response.
    //     // Please refer to comments in `http_seen_before` for more context.
    //     if (http->tcp_seq == HTTP_TERMINATING) {
    //         bpf_map_delete_elem(&http_in_flight, &http_class->tuple);
    //     }
    // }
    // Instead we use the old version.
    if (http_closed(skb_info)) {
        // Since we wait the next transaction to flush the data in userspace, the last trasaction should be flushed here.
        http_batch_enqueue_wrapper(&http_class->tuple, http);
        bpf_map_delete_elem(&http_in_flight, &http_class->tuple);
    }
}

static __always_inline bool is_watch_api_candidate(http_classification_t *http_class) {
    // K8s watch API detection:
    //
    // We try to detect the typical k8s query path
    // - /api/v (for core resources, e.g. pod)
    // - /apis/ (for other resources, e.g. deployments)
    // As a common prefix we search `/api`
    // GET /api
    // 01234567
    // So we need to start from index 4
    return http_class->packet_type == HTTP_REQUEST &&
            http_class->method == HTTP_GET &&
            http_class->request_fragment[4] == '/' &&
            http_class->request_fragment[5] == 'a' &&
            http_class->request_fragment[6] == 'p' &&
            http_class->request_fragment[7] == 'i';
}

SEC("socket/http_filter")
int socket__http_filter(struct __sk_buff* skb) {
    skb_info_t skb_info;
    http_classification_t http_class;
    bpf_memset(&http_class, 0, sizeof(http_classification_t));

    if (!fetch_dispatching_arguments(&http_class.tuple, &skb_info)) {
        log_debug("http_filter failed to fetch arguments for tail call");
        return 0;
    }
    // bpf_printk("[socket filter]: tcp_seq=%u, tcp_flags=%d, src port: %d", skb_info.tcp_seq, skb_info.tcp_flags, http_class.tuple.sport);

    http_classify_skb(&http_class, &skb_info, skb);

    if (is_watch_api_candidate(&http_class)) {
        __u32 zero = 0;
        // we need to store the tracing ID so that we can reuse that if we don't find `watch=true`
        http_store_tracing_id_t *store = bpf_map_lookup_elem(&http_store_tracing_id, &zero);
        if (store) {
            bpf_memcpy(store->tracing_id, http_class.tracing_id, HTTP_TRACING_ID_SIZE);
            store->parse_result = http_class.parse_result;
        }
        bpf_tail_call_compat(skb, &protocols_progs, PROG_HTTP_WATCH_API_MANAGEMENT);
        return 0;
    }

    // STS: Putting normalize after classify, because any branching in front of trace parsing may double the instruction count
    normalize_tuple(&http_class.tuple);

    http_process(&http_class, &skb_info, NO_TAGS);
    return 0;
}

SEC("socket/http_watch_api_management")
int socket__http_watch_api_management(struct __sk_buff* skb) {
    skb_info_t skb_info;
    http_classification_t http_class;
    bpf_memset(&http_class, 0, sizeof(http_classification_t));

    if (!fetch_dispatching_arguments(&http_class.tuple, &skb_info)) {
        log_debug("http_watch_api_management failed to fetch arguments for tail call");
        return 0;
    }

    __u64 tags = NO_TAGS;
    bool watch_found = http_find_watch_true_skb(skb, &skb_info);
    if (watch_found) {
        // no need to recover the tracing ID from the per-CPU map since we won't use that in userspace
        // with the watch tag.
        tags = WATCH_API;
    } else {
        // we need to recover the tracing ID from the per-CPU map
        __u32 zero = 0;
        http_store_tracing_id_t *store = bpf_map_lookup_elem(&http_store_tracing_id, &zero);
        if (store) {
            bpf_memcpy(http_class.tracing_id, store->tracing_id, HTTP_TRACING_ID_SIZE);
            http_class.parse_result = store->parse_result;
        }
    }
    read_into_buffer_skb((char *)http_class.request_fragment, skb, skb_info.data_off);
    http_class.method = HTTP_GET;
    http_class.packet_type = HTTP_REQUEST;

    // bpf_my_printk("tag %llu, type: %d, path: %s", tags, http_class.packet_type, http_class.request_fragment);

    normalize_tuple(&http_class.tuple);

    http_process(&http_class, &skb_info, tags);
    return 0;
}

SEC("uprobe/http_process")
int uprobe__http_process(struct pt_regs *ctx) {
    const __u32 zero = 0;
    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (args == NULL) {
        return 0;
    }

    http_classification_t http_class;
    bpf_memset(&http_class, 0, sizeof(http_classification_t));
    bpf_memcpy(&http_class.tuple, &args->tup, sizeof(conn_tuple_t));

    http_classify_user(&http_class, args->buffer_ptr, args->data_end);

    http_process(&http_class, NULL, args->tags);
    http_batch_flush(ctx);

    return 0;
}

SEC("uprobe/http_termination")
int uprobe__http_termination(struct pt_regs *ctx) {
    const __u32 zero = 0;
    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (args == NULL) {
        return 0;
    }

    http_classification_t http_class;
    bpf_memset(&http_class, 0, sizeof(http_classification_t));
    bpf_memcpy(&http_class.tuple, &args->tup, sizeof(conn_tuple_t));
    skb_info_t skb_info = {0};
    skb_info.tcp_flags |= TCPHDR_FIN;
    http_process(&http_class, &skb_info, NO_TAGS);
    http_batch_flush(ctx);

    return 0;
}

#endif
