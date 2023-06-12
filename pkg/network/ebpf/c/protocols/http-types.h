#ifndef __HTTP_TYPES_H
#define __HTTP_TYPES_H

#include "tracer.h"

// This determines the size of the payload fragment that is captured for each HTTP request
#define HTTP_BUFFER_SIZE (8 * 20)
// This determines the size of the tracing id; we expect a 288 bit UUID => 16 bytes + null termination
#define HTTP_TRACING_ID_SIZE 37
// x-trace-id: 16266295-c3fa-4fae-994c-b35f1d02c1c8
#define HTTP_TRACING_ID_HEADER_SIZE 49
//
#define HTTP_RESPONSE_STATUS_LINE_MAX_SIZE 25
//
#define HTTP_HEADER_LIMIT 8190
// This controls the number of HTTP transactions read from userspace at a time
#define HTTP_BATCH_SIZE 14

// HTTP/1.1 XXX
// _________^
#define HTTP_STATUS_OFFSET 9

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

// HTTP transaction information associated to a certain socket (tuple_t)
typedef struct {
    conn_tuple_t tup;
    __u64 request_started;
    __u8  request_method;
    __u16 response_status_code;
    __u64 response_last_seen;
    char request_fragment[HTTP_BUFFER_SIZE] __attribute__ ((aligned (8)));

    // this field is used exclusively in the kernel side to prevent a TCP segment
    // to be processed twice in the context of localhost traffic. The field will
    // be populated with the "original" (pre-normalization) source port number of
    // the TCP segment containing the beginning of a given HTTP request
    __u16 owned_by_src_port;

    // this field is used to disambiguate segments in the context of keep-alives
    // we populate it with the TCP seq number of the request and then the response segments
    __u32 tcp_seq;

    __u64 tags;

    // used as a correlation id to correlate different observations of the same connection.
    char tracing_id[HTTP_TRACING_ID_SIZE];
} http_transaction_t;

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

#define LIB_PATH_MAX_SIZE 120

typedef struct {
    __u32 pid;
    __u32 len;
    char buf[LIB_PATH_MAX_SIZE];
} lib_path_t;

typedef struct {
    __u32 matches;
    __u32 position;
} trace_match_t;

typedef enum
{
    NO_MATCH,
    PARTIAL_MATCH,
    FULL_MATCH
} trace_header_match_t;


#endif
