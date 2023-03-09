#ifndef __HTTP_TYPES_H
#define __HTTP_TYPES_H

#include "conn_tuple.h"

// This determines the size of the payload fragment that is captured for each HTTP request
#define HTTP_BUFFER_SIZE (8 * 26)
// This controls the number of HTTP transactions read from userspace at a time
#define HTTP_BATCH_SIZE 10

// HTTP/1.1 XXX
// _________^
#define HTTP_STATUS_OFFSET 9

// Pseudo TCP sequence number representing a segment with a FIN or RST flags set
// For more information see `http_seen_before`
#define HTTP_TERMINATING 0xFFFFFFFF

// The key of the http-tracing-id header, including leading newline: \nx-trace-id:
#define HTTP_TRACING_ID_KEY_SIZE 14
// These arrays are made 256 big, to always have the situation that indexing into it can be done. In practice we'll never index
// beyond the values, but ebpf can't prove it.
static char http_tracing_header_key_lower[256] = { '\n', 'x', '-', 'r', 'e', 'q', 'u', 'e', 's', 't', '-', 'i', 'd', ':' };
static char http_tracing_header_key_upper[256] = { '\n', 'X', '-', 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '-', 'I', 'D', ':' };

// Full uuid+ newline and a bit.
#define HTTP_TRACING_ID_SIZE 40

#define HTTP_HEADER_READ_BUFFER_SIZE 10 // This number is picked such that we do not loose too much data when the last batch does not exactly match.
#define HTTP_HEADER_READ_LIMIT 1500 // This should be a multiple of HTTP_HEADER_READ_BUFFER_SIZE
#define HTTP_BATCH_COUNT 150 //

// This is needed to reduce code size on multiple copy opitmizations that were made in
// the http eBPF program.
_Static_assert((HTTP_BUFFER_SIZE % 8) == 0, "HTTP_BUFFER_SIZE must be a multiple of 8.");

typedef enum
{
    HTTP_PACKET_UNKNOWN,
    HTTP_REQUEST,
    HTTP_RESPONSE
} http_packet_t;

typedef enum
{
    HTTP_METHOD_UNKNOWN,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH
} http_method_t;

typedef enum {
  NO_HEADER_PARSE,
  HEADER_PARSE_FOUND,
  HEADER_PARSE_NOT_FOUND,
  HEADER_PARSE_LIMIT_REACHED,
  HEADER_PARSE_PACKET_END_REACHED
} header_parse_result_t;

// HTTP transaction information associated to a certain socket (conn_tuple_t)
typedef struct {
    __u64 request_started;
    __u64 response_last_seen;
    __u64 tags;
    // this field is used to disambiguate segments in the context of keep-alives
    // we populate it with the TCP seq number of the request and then the response segments
    __u32 tcp_seq;
    __u16 response_status_code;
    __u8  request_method;
    char request_fragment[HTTP_BUFFER_SIZE] __attribute__ ((aligned (8)));

    // used as a correlation id to correlate different observations of the same connection.
    char request_tracing_id[HTTP_TRACING_ID_SIZE] __attribute__ ((aligned (8)));
    char response_tracing_id[HTTP_TRACING_ID_SIZE] __attribute__ ((aligned (8)));

    __u8 request_parse_result;
    __u8 response_parse_result;
} http_transaction_t;

typedef struct {
    conn_tuple_t tuple;
    http_transaction_t http;
} http_event_t;

typedef struct {
    conn_tuple_t tuple;

    char request_fragment[HTTP_BUFFER_SIZE] __attribute__ ((aligned (8)));

    http_packet_t packet_type;
    http_method_t method;

    char tracing_id[HTTP_TRACING_ID_SIZE] __attribute__ ((aligned (8)));
    header_parse_result_t parse_result;
} http_classification_t;

// OpenSSL types
typedef struct {
    void *ctx;
    void *buf;
} ssl_read_args_t;

typedef struct {
    void *ctx;
    void *buf;
} ssl_write_args_t;

typedef struct {
    void *ctx;
    void *buf;
    size_t *size_out_param;
} ssl_read_ex_args_t;

typedef struct {
    void *ctx;
    void *buf;
    size_t *size_out_param;
} ssl_write_ex_args_t;

typedef struct {
    conn_tuple_t tup;
    __u32 fd;
} ssl_sock_t;

typedef struct {
    // The position in the header at which we should next find a match. Start at 0 to match the leading '\n' of a header.
    __u8 match_position;
} trace_match_t;

/*
Return codes to use while parsing.
*/
typedef enum
{
    COMPLETE_MATCH,
    CONTINUE_MATCH,
} trace_header_match_t;

#endif
