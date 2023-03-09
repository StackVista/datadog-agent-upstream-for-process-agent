#ifndef BPF_UNIFIED_BUFFER_ACCESS_H
#define BPF_UNIFIED_BUFFER_ACCESS_H

#include "bpf_telemetry.h"
#include <sys/errno.h>

typedef enum {
	BPF_BUFFER_TYPE_UNKNOWN = 0, // Unknown buffer type, can not be read or written
	BPF_BUFFER_TYPE_SKB = 1, // Socket buffer, buffer will be (struct __sk_buff *)
	BPF_BUFFER_TYPE_USER = 2, // User space buffer
} bpf_buffer_type_t;

/**
 * ebpf_buffer_desc_t is a structure that represents a buffer that can be read or written by an eBPF program.
 * The buffer can be of different types, such as a socket buffer or a user space buffer.
*/
typedef struct {
	bpf_buffer_type_t type; // Type of the buffer
	void *ptr; // Pointer to the buffer
	__u32 data_offset; // Offset in the buffer where the data starts.
} bpf_buffer_desc_t;

// Generalized function to load data from either a packet or a user-space buffer.
// Reads `len` bytes from `offset` in `buffer` and stores them in `to`.
// The buffer described in `buffer` must be of type `EBPF_BUFFER_TYPE_SKB` or `EBPF_BUFFER_TYPE_USER`.
// The `offset` parameter is in addition to any `data_offset` specified in `buffer`.
// Returns 0 on success, or a negative error code on failure.
static __always_inline int bpf_load_data(const bpf_buffer_desc_t *buffer, __u32 offset, void *to, __u32 len) {
	if (buffer == NULL || buffer->ptr == NULL || to == NULL) {
		log_debug("bpf_load_data: invalid descriptor (%p) or buffer (%p) or target (%p)", buffer, buffer->ptr, to);
		return -EINVAL;
	}
	
	if (buffer->type == BPF_BUFFER_TYPE_SKB) {
		return bpf_skb_load_bytes_with_telemetry(buffer->ptr, buffer->data_offset + offset, to, len);
	} else if (buffer->type == BPF_BUFFER_TYPE_USER) {
		return bpf_probe_read_user_with_telemetry(to, len, buffer->ptr + buffer->data_offset + offset);
	} else {
		log_debug("bpf_load_data: unknown buffer type %d", buffer->type);
		return -EINVAL;
	}
}

#endif
