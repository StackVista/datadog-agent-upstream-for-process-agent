#ifndef __HTTP_H
#define __HTTP_H

#include "bpf_builtins.h"
#include "bpf_telemetry.h"
#include "tracer.h"
#include "http-types.h"
#include "http-maps.h"
#include "https.h"
#include "events.h"
#include "bpf_helpers.h"

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

static const __u8 matched_newline_position = 1;
static const __u8 carriage_return = '\r';

/*
Parse the content of the current read buffer.
*/
static __always_inline void http_read_headers_skb(struct __sk_buff* skb, skb_info_t *skb_info, char *output_buffer, header_parse_result_t *parse_result) {
  // loading in chunks, because bpf_skb_load_bytes does a lot of checks, such that per-byte reading exceeds the 1m instruction limit.
  char read_buffer[HTTP_HEADER_READ_BUFFER_SIZE];
  bpf_memset((char*)read_buffer, 0, HTTP_HEADER_READ_BUFFER_SIZE);

  // We round down the batch count. This is ok, because we match the header key,
  // so the last bytes, if they would be interesting, would be the header value.
  const __u64 batch_count = skb_info->data_length / HTTP_HEADER_READ_BUFFER_SIZE;

  __u64 skb_offset = skb_info->data_off;

  // Matching state, how much of the header have we already matched?
  __u8 match_position = 0;

#pragma unroll HTTP_BATCH_COUNT
  for (__u64 batch = 0; batch < HTTP_BATCH_COUNT; batch++)
  {
    // Using batching to limit the amount of syscalls
    bpf_skb_load_bytes(skb, skb_offset, &read_buffer[0], HTTP_HEADER_READ_BUFFER_SIZE);

    // It is ok to check the batch count after the load, because the failre will be silent, no crashes here.
    __u8 offset_done_unequal_boolean = __bpf_no_branch_cmp_unequal(batch, batch_count);

#pragma unroll HTTP_HEADER_READ_BUFFER_SIZE
    for (__u64 offset = 0; offset < HTTP_HEADER_READ_BUFFER_SIZE; offset++) {
      /**
        Stopping condition: Breaking out of the loop can be done with a conditional, because it does not increase the cyclomatic complexity much
        (the amount of possible execution paths does not go up by a lot).

        Using quirky logic here, see below explanation why boolean logic is bad in loops. Also, by adding too many conditionals
        in the loop will cause the loop to not unroll.
        Stopping conditions:
        - We found the HEADER
        - We are at the limit of what we want to read.
        - We are at the end of the header section. This is determined by:
            -- The match_position is 1, meaning we read a \n. And the current char is \r. This signifies the \r\n\r\n at the end of header section unambiguously.
      */
      __u8 match_done_unequal_boolean = __bpf_no_branch_cmp_unequal(match_position, HTTP_TRACING_ID_KEY_SIZE);

      __u8 match_position_one_unequal_boolean = __bpf_no_branch_cmp_unequal(match_position, matched_newline_position);
      __u8 match_position_carriage_return_unequal_boolean = __bpf_no_branch_cmp_unequal(read_buffer[offset], carriage_return);
      __u8 end_of_header_unequal_boolean = match_position_one_unequal_boolean | match_position_carriage_return_unequal_boolean;

      __u8 match_and_offset_unequal_boolean = match_done_unequal_boolean & offset_done_unequal_boolean & end_of_header_unequal_boolean;

      if (__bpf_no_branch_neg(match_and_offset_unequal_boolean)) {
        goto done;
      }

      /**
      Okay, here it goes:
      We cannot have any branching inside this loop (which has many iterations), because each iteration the possible execution path
      count might double if there are multiple branches. EBPF verifier counts all execution patch for its instruction, so that would not be good.

      We want to do the header parsing here without any branching. However, in ebpf bytecode simple comparisons are implemented using jumps, so thats
      an issue...

      What we do here is implement comparison and parsing using the available operators on ebpf, by avoid branching. Equality is replaced byt XOR for example.

      Matching of the header value is case insensitive.

      References:
      https://docs.kernel.org/bpf/instruction-set.html
      https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/BPF/BPFInstrInfo.td
      https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/
      https://github.com/cilium/cilium/blob/main/bpf/include/bpf/ctx/xdp.h
     */
      __u8 not_equal_lower_boolean = __bpf_no_branch_cmp_unequal(read_buffer[offset],  http_tracing_header_key_lower[match_position]);
      __u8 not_equal_upper_boolean = __bpf_no_branch_cmp_unequal(read_buffer[offset],  http_tracing_header_key_upper[match_position]);
      __u8 not_equal_boolean = not_equal_lower_boolean & not_equal_upper_boolean; // Are both unequal?
      __u8 equal_boolean = __bpf_no_branch_neg(not_equal_boolean); // Turn inequality to equality. Is one of the matches equal?

      // Increase the position when we have a match
      match_position += equal_boolean;

      // Clear the position when we have a mismatch
      __u64 clear_mask = __bpf_no_branch_true_mask(equal_boolean);
      match_position &= clear_mask;

      skb_offset++;
    }
  }

done:
  if (match_position >= HTTP_TRACING_ID_KEY_SIZE) {
    /* did we get a complete match of the tracing id? Lets copy the content of the data. This misses a couple of validations:
     - Is the field value actually 36 bytes long? Is it a UUID? these are all things that will be figured out in go.
    */
    __u64 load_size = skb->len - skb_offset;
    if (load_size > HTTP_TRACING_ID_SIZE) {
      load_size = HTTP_TRACING_ID_SIZE;
    }
    bpf_skb_load_bytes(skb, skb_offset, output_buffer, HTTP_TRACING_ID_SIZE);
    output_buffer[HTTP_TRACING_ID_SIZE - 1] = '\0';

    *parse_result = HEADER_PARSE_FOUND;
  } else {
    skb_offset -= skb_info->data_off;

    if (skb_offset < skb_info->data_length) {
      // Not parsed till the end?
      if (skb_offset >= HTTP_HEADER_READ_LIMIT) {
        *parse_result = HEADER_PARSE_LIMIT_REACHED;
      } else {
        *parse_result = HEADER_PARSE_NOT_FOUND;
      }
    } else {
      *parse_result = HEADER_PARSE_PACKET_END_REACHED;
    }
  }
}

/*
Parse the content of the current read buffer.
*/
static __always_inline void http_read_headers_user(char* data, __u64 length, char *output_buffer, header_parse_result_t *parse_result) {
  // loading in chunks, because bpf_skb_load_bytes does a lot of checks, such that per-byte reading exceeds the 1m instruction limit.
  char read_buffer[HTTP_HEADER_READ_BUFFER_SIZE];
  bpf_memset((char*)read_buffer, 0, HTTP_HEADER_READ_BUFFER_SIZE);

  // We round down the batch count. This is ok, because we match the header key,
  // so the last bytes, if they would be interesting, would be the header value.
  const __u64 batch_count = length / HTTP_HEADER_READ_BUFFER_SIZE;

  __u64 skb_offset = 0;

  // Matching state, how much of the header have we already matched?
  __u8 match_position = 0;

#pragma unroll HTTP_BATCH_COUNT
  for (__u64 batch = 0; batch < HTTP_BATCH_COUNT; batch++)
  {
    // Using batching to limit the amount of syscalls
    bpf_probe_read_user(&read_buffer[0], HTTP_HEADER_READ_BUFFER_SIZE, &data[batch * HTTP_HEADER_READ_BUFFER_SIZE]);

    // It is ok to check the batch count after the load, because the failre will be silent, no crashes here.
    __u8 offset_done_unequal_boolean = __bpf_no_branch_cmp_unequal(batch, batch_count);

#pragma unroll HTTP_HEADER_READ_BUFFER_SIZE
    for (__u64 offset = 0; offset < HTTP_HEADER_READ_BUFFER_SIZE; offset++) {
      /**
        Stopping condition: Breaking out of the loop can be done with a conditional, because it does not increase the cyclomatic complexity much
        (the amount of possible execution paths does not go up by a lot).

        Using quirky logic here, see below explanation why boolean logic is bad in loops. Also, by adding too many conditionals
        in the loop will cause the loop to not unroll.
        Stopping conditions:
        - We found the HEADER
        - We are at the limit of what we want to read.
        - We are at the end of the header section. This is determined by:
            -- The match_position is 1, meaning we read a \n. And the current char is \r. This signifies the \r\n\r\n at the end of header section unambiguously.
      */
      __u8 match_done_unequal_boolean = __bpf_no_branch_cmp_unequal(match_position, HTTP_TRACING_ID_KEY_SIZE);

      __u8 match_position_one_unequal_boolean = __bpf_no_branch_cmp_unequal(match_position, matched_newline_position);
      __u8 match_position_carriage_return_unequal_boolean = __bpf_no_branch_cmp_unequal(read_buffer[offset], carriage_return);
      __u8 end_of_header_unequal_boolean = match_position_one_unequal_boolean | match_position_carriage_return_unequal_boolean;

      __u8 match_and_offset_unequal_boolean = match_done_unequal_boolean & offset_done_unequal_boolean & end_of_header_unequal_boolean;

      if (__bpf_no_branch_neg(match_and_offset_unequal_boolean)) {
        goto done;
      }

      /**
      Okay, here it goes:
      We cannot have any branching inside this loop (which has many iterations), because each iteration the possible execution path
      count might double if there are multiple branches. EBPF verifier counts all execution patch for its instruction, so that would not be good.

      We want to do the header parsing here without any branching. However, in ebpf bytecode simple comparisons are implemented using jumps, so thats
      an issue...

      What we do here is implement comparison and parsing using the available operators on ebpf, by avoid branching. Equality is replaced byt XOR for example.

      Matching of the header value is case insensitive.

      References:
      https://docs.kernel.org/bpf/instruction-set.html
      https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/BPF/BPFInstrInfo.td
      https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/
      https://github.com/cilium/cilium/blob/main/bpf/include/bpf/ctx/xdp.h
     */
      __u8 not_equal_lower_boolean = __bpf_no_branch_cmp_unequal(read_buffer[offset],  http_tracing_header_key_lower[match_position]);
      __u8 not_equal_upper_boolean = __bpf_no_branch_cmp_unequal(read_buffer[offset],  http_tracing_header_key_upper[match_position]);
      __u8 not_equal_boolean = not_equal_lower_boolean & not_equal_upper_boolean; // Are both unequal?
      __u8 equal_boolean = __bpf_no_branch_neg(not_equal_boolean); // Turn inequality to equality. Is one of the matches equal?

      // Increase the position when we have a match
      match_position += equal_boolean;

      // Clear the position when we have a mismatch
      __u64 clear_mask = __bpf_no_branch_true_mask(equal_boolean);
      match_position &= clear_mask;

      skb_offset++;
    }
  }

done:
  if (match_position >= HTTP_TRACING_ID_KEY_SIZE) {
    /* did we get a complete match of the tracing id? Lets copy the content of the data. This misses a couple of validations:
     - Is the field value actually 36 bytes long? Is it a UUID? these are all things that will be figured out in go.
    */
    __u64 load_size = length - skb_offset;
    if (load_size > HTTP_TRACING_ID_SIZE) {
      load_size = HTTP_TRACING_ID_SIZE;
    }

    bpf_probe_read_user(output_buffer, HTTP_TRACING_ID_SIZE, &data[skb_offset]);

    output_buffer[HTTP_TRACING_ID_SIZE - 1] = '\0';

    *parse_result = HEADER_PARSE_FOUND;
  } else {
    if (skb_offset < length) {
      // Not parsed till the end?
      if (skb_offset >= HTTP_HEADER_READ_LIMIT) {
        *parse_result = HEADER_PARSE_LIMIT_REACHED;
      } else {
        *parse_result = HEADER_PARSE_NOT_FOUND;
      }
    } else {
      *parse_result = HEADER_PARSE_PACKET_END_REACHED;
    }
  }
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

static __always_inline __u8 http_is_req_resp(char const *p) {
  // [STS] Using no-branching logic to reduce number of branches. Could be optimized further by using masking.
  __u8 is_response = __bpf_no_branch_neg(
          __bpf_no_branch_cmp_unequal(p[0], 'H') |
          __bpf_no_branch_cmp_unequal(p[1], 'T') |
          __bpf_no_branch_cmp_unequal(p[2], 'T') |
          __bpf_no_branch_cmp_unequal(p[3], 'P')
       );

  __u8 is_get = __bpf_no_branch_neg(
                               __bpf_no_branch_cmp_unequal(p[0], 'G') |
                               __bpf_no_branch_cmp_unequal(p[1], 'E') |
                               __bpf_no_branch_cmp_unequal(p[2], 'T') |
                               __bpf_no_branch_cmp_unequal(p[3], ' ') |
                               __bpf_no_branch_cmp_unequal(p[4], '/')
                            );

  __u8 is_post = __bpf_no_branch_neg(
                               __bpf_no_branch_cmp_unequal(p[0], 'P') |
                               __bpf_no_branch_cmp_unequal(p[1], 'O') |
                               __bpf_no_branch_cmp_unequal(p[2], 'S') |
                               __bpf_no_branch_cmp_unequal(p[3], 'T') |
                               __bpf_no_branch_cmp_unequal(p[4], ' ') |
                               __bpf_no_branch_cmp_unequal(p[5], '/')
                            );

  __u8 is_put = __bpf_no_branch_neg(
                               __bpf_no_branch_cmp_unequal(p[0], 'P') |
                               __bpf_no_branch_cmp_unequal(p[1], 'U') |
                               __bpf_no_branch_cmp_unequal(p[2], 'T') |
                               __bpf_no_branch_cmp_unequal(p[3], ' ') |
                               __bpf_no_branch_cmp_unequal(p[4], '/')
                            );

  __u8 is_delete = __bpf_no_branch_neg(
                                  __bpf_no_branch_cmp_unequal(p[0], 'D') |
                                  __bpf_no_branch_cmp_unequal(p[1], 'E') |
                                  __bpf_no_branch_cmp_unequal(p[2], 'L') |
                                  __bpf_no_branch_cmp_unequal(p[3], 'E') |
                                  __bpf_no_branch_cmp_unequal(p[4], 'T') |
                                  __bpf_no_branch_cmp_unequal(p[5], 'E') |
                                  __bpf_no_branch_cmp_unequal(p[6], ' ') |
                                  __bpf_no_branch_cmp_unequal(p[7], '/')
                               );

  __u8 is_head = __bpf_no_branch_neg(
                                __bpf_no_branch_cmp_unequal(p[0], 'H') |
                                __bpf_no_branch_cmp_unequal(p[1], 'E') |
                                __bpf_no_branch_cmp_unequal(p[2], 'A') |
                                __bpf_no_branch_cmp_unequal(p[3], 'D') |
                                __bpf_no_branch_cmp_unequal(p[4], ' ') |
                                __bpf_no_branch_cmp_unequal(p[5], '/')
                             );

  __u8 is_options = __bpf_no_branch_neg(
                                   __bpf_no_branch_cmp_unequal(p[0], 'O') |
                                   __bpf_no_branch_cmp_unequal(p[1], 'P') |
                                   __bpf_no_branch_cmp_unequal(p[2], 'T') |
                                   __bpf_no_branch_cmp_unequal(p[3], 'I') |
                                   __bpf_no_branch_cmp_unequal(p[4], 'O') |
                                   __bpf_no_branch_cmp_unequal(p[5], 'N') |
                                   __bpf_no_branch_cmp_unequal(p[6], 'S') |
                                   __bpf_no_branch_cmp_unequal(p[7], ' ') |
                                   (__bpf_no_branch_cmp_unequal(p[8], '/') & __bpf_no_branch_cmp_unequal(p[8], '*'))
                                );

  __u8 is_patch = __bpf_no_branch_neg(
                                 __bpf_no_branch_cmp_unequal(p[0], 'P') |
                                 __bpf_no_branch_cmp_unequal(p[1], 'A') |
                                 __bpf_no_branch_cmp_unequal(p[2], 'T') |
                                 __bpf_no_branch_cmp_unequal(p[3], 'C') |
                                 __bpf_no_branch_cmp_unequal(p[4], 'H') |
                                 __bpf_no_branch_cmp_unequal(p[5], ' ') |
                                 __bpf_no_branch_cmp_unequal(p[6], '/')
                              );

  return is_response | is_get | is_post | is_put | is_delete | is_head | is_options | is_patch;
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

static __always_inline void http_ensure_tcp(http_transaction_t *http, http_classification_t *http_class) {
    bpf_memcpy(&http->tup, &http_class->tup, sizeof(conn_tuple_t));
    http->owned_by_src_port = http_class->owned_by_src_port;
}

/** Global empty value to assist with initialization of the mpa items.
*/
static http_transaction_t init_zero;

static __always_inline http_transaction_t *http_fetch_state(http_classification_t *http_class, http_packet_t packet_type) {
    if (packet_type == HTTP_PACKET_UNKNOWN) {
        return bpf_map_lookup_elem(&http_in_flight, &http_class->tup);
    }

    // We detected either a request or a response
    // In this case we initialize (or fetch) state associated to this tuple
    long new_created = bpf_map_update_with_telemetry(http_in_flight, &http_class->tup, &init_zero, BPF_NOEXIST);
    http_transaction_t *http =  bpf_map_lookup_elem(&http_in_flight, &http_class->tup);

    if (http && new_created == 0) {
      http_ensure_tcp(http, http_class);
    }

    return http;
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

static __always_inline void http_classify_skb(http_classification_t *http_class, skb_info_t *skb_info, struct __sk_buff *skb) {
  char *buffer = (char *)http_class->request_fragment;
  read_into_buffer_skb(buffer, skb, skb_info);

  // [STS]: Disabling logs to reduce instruction count
  // log_debug("http_process: type=%d method=%d\n", packet_type, method);

  // We need an optimized version here to determine whether we have encountered a req or response.
  if (http_is_req_resp(buffer)) {
    http_read_headers_skb(skb, skb_info, (char*)http_class->tracing_id, &http_class->parse_result);
  }

  http_parse_data(buffer, &http_class->packet_type, &http_class->method);
}

static __always_inline void http_classify_user(http_classification_t *http_class, char *data, size_t len) {
  char *buffer = (char *)http_class->request_fragment;
  read_into_buffer(buffer, data, len);

  // We need an optimized version here to determine whether we have encountered a req or response.
  if (http_is_req_resp(buffer)) {
    http_read_headers_user(data, len, (char*)http_class->tracing_id, &http_class->parse_result);
  }

  http_parse_data(buffer, &http_class->packet_type, &http_class->method);
}

static __always_inline int http_process(http_classification_t *http_class, skb_info_t *skb_info, __u64 tags) {
    char *buffer = (char *)http_class->request_fragment;

    http_transaction_t *http = http_fetch_state(http_class, http_class->packet_type);
    if (!http || http_seen_before(http, skb_info)) {
        return 0;
    }

    if (http_should_flush_previous_state(http, http_class->packet_type)) {
        http_batch_enqueue(http);
        bpf_memset(http, 0, sizeof(http_transaction_t));
        http_ensure_tcp(http, http_class);
    }

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
    }

    http->tags |= tags;

    // STS Addition: Only set the response time when there is actual data flowing, to
    // avoid a delayed connection close with no data (empty FIN packet) falsely increases the latency.
    if (http_responding(http) && skb_info && skb_info->data_length != 0) {
        http->response_last_seen = bpf_ktime_get_ns();
    }

    if (http_closed(http, skb_info, http_class->owned_by_src_port)) {
        http_batch_enqueue(http);
        bpf_map_delete_elem(&http_in_flight, &http_class->tup);
    }

    return 0;
}

// this function is called by the socket-filter program to decide whether or not we should inspect
// the contents of a certain packet, in order to avoid the cost of processing packets that are not
// of interest such as empty ACKs, UDP data or encrypted traffic.
static __always_inline bool http_allow_packet(http_classification_t *http_class, struct __sk_buff* skb, skb_info_t *skb_info) {
    // we're only interested in TCP traffic
    if (!(http_class->tup.metadata&CONN_TYPE_TCP)) {
        return false;
    }

    // if payload data is empty or if this is an encrypted packet, we only
    // process it if the packet represents a TCP termination
    bool empty_payload = skb_info->data_off == skb->len;
    if (empty_payload || http_class->tup.sport == HTTPS_PORT || http_class->tup.dport == HTTPS_PORT) {
        return skb_info->tcp_flags&(TCPHDR_FIN|TCPHDR_RST);
    }

    return true;
}


#endif
