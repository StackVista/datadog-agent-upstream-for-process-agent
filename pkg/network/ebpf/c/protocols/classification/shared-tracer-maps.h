#ifndef __PROTOCOL_CLASSIFICATION_SHARED_TRACER_MAPS_H
#define __PROTOCOL_CLASSIFICATION_SHARED_TRACER_MAPS_H

#include "map-defs.h"
#include "ip.h"
#include "port_range.h"
#include "protocols/classification/stack-helpers.h"

// Maps a connection tuple to its classified protocol. Used to reduce redundant
// classification procedures on the same connection
BPF_HASH_MAP(connection_protocol, conn_tuple_t, protocol_stack_wrapper_t, 0)

static __always_inline bool is_protocol_classification_supported() {
    __u64 val = 0;
    LOAD_CONSTANT("protocol_classification_enabled", val);
    return val > 0;
}

// [STS] Shared by the tracer and USM, so every hook that sees a connection
// spends from one budget. Resized from userspace.
BPF_LRU_MAP(classify_budget, conn_tuple_t, classification_budget_t, 16384)

BPF_ARRAY_MAP(classify_telemetry, classification_budget_telemetry_t, 1)

static __always_inline bool is_loopback_tuple(conn_tuple_t *tuple) {
    if (tuple->metadata & CONN_V6) {
        return tuple->saddr_h == 0 && tuple->saddr_l == bpf_ntohll(1);
    }
    return (bpf_ntohl((__u32)tuple->saddr_l) >> 24) == 127;
}

// [STS] Hooks disagree on netns: the classifier leaves it unset and the
// dispatchers set their own. Only loopback tuples repeat across namespaces,
// so only they keep it.
static __always_inline bool classification_budget_key(conn_tuple_t *tuple, conn_tuple_t *key) {
    *key = *tuple;
    if (!is_loopback_tuple(key)) {
        key->netns = 0;
    }
    return normalize_tuple(key);
}

static __always_inline __u32 classification_budget(bool handshake_seen) {
    __u64 val = 0;
    if (handshake_seen) {
        LOAD_CONSTANT("classification_budget_handshake", val);
        if (val == 0) {
            val = CLASSIFICATION_DEFAULT_BUDGET_HANDSHAKE;
        }
    } else {
        LOAD_CONSTANT("classification_budget_mid_stream", val);
        if (val == 0) {
            val = CLASSIFICATION_DEFAULT_BUDGET_MID_STREAM;
        }
    }
    return val > 0xffff ? 0xffff : (__u32)val;
}

// [STS] A SYN starts a connection, or reuses a tuple, so it resets the budget.
static __always_inline void mark_classification_handshake_seen(conn_tuple_t *tuple) {
    conn_tuple_t key;
    classification_budget_key(tuple, &key);
    classification_budget_t budget = {0};
    budget.flags = CLASSIFICATION_HANDSHAKE_SEEN;
    bpf_map_update_elem(&classify_budget, &key, &budget, BPF_ANY);
}

// [STS] Constant indices only: a variable index into a stack array compiles
// to pointer arithmetic the verifier rejects.
static __always_inline __u32 *classification_last_seq(classification_budget_t *budget, bool dir) {
    return dir ? &budget->last_seq[1] : &budget->last_seq[0];
}

// [STS] Spends one segment of the budget of a connection whose application
// protocol is unknown. Returns false once the budget is exhausted; the caller
// must then skip classification. Segments already counted, by another hook or
// as a retransmission, are inspected without spending. Concurrent updates may
// lose an increment, which only stretches the budget slightly.
static __always_inline bool spend_classification_attempt(conn_tuple_t *tuple, skb_info_t *skb_info) {
    conn_tuple_t key;
    const __u32 dir = classification_budget_key(tuple, &key) ? 1 : 0;
    classification_budget_t *budget = bpf_map_lookup_elem(&classify_budget, &key);
    if (!budget) {
        classification_budget_t fresh = {0};
        fresh.segments = 1;
        fresh.flags = CLASSIFICATION_SEQ_SEEN(dir);
        *classification_last_seq(&fresh, dir) = skb_info->tcp_seq;
        bpf_map_update_elem(&classify_budget, &key, &fresh, BPF_NOEXIST);
        return true;
    }

    if (budget->flags & CLASSIFICATION_GAVE_UP) {
        if (bpf_ktime_get_ns() - budget->gave_up_at < CLASSIFICATION_RETRY_NS) {
            return false;
        }
        budget->flags &= CLASSIFICATION_HANDSHAKE_SEEN;
        budget->segments = 0;
    }

    __u32 *last_seq = classification_last_seq(budget, dir);
    if ((budget->flags & CLASSIFICATION_SEQ_SEEN(dir)) && (__s32)(skb_info->tcp_seq - *last_seq) <= 0) {
        return true;
    }
    budget->flags |= CLASSIFICATION_SEQ_SEEN(dir);
    *last_seq = skb_info->tcp_seq;

    const bool handshake = budget->flags & CLASSIFICATION_HANDSHAKE_SEEN;
    if (budget->segments < classification_budget(handshake)) {
        budget->segments++;
        return true;
    }

    budget->flags |= CLASSIFICATION_GAVE_UP;
    budget->gave_up_at = bpf_ktime_get_ns();
    const __u32 zero = 0;
    classification_budget_telemetry_t *telemetry = bpf_map_lookup_elem(&classify_telemetry, &zero);
    if (telemetry) {
        __sync_fetch_and_add(&telemetry->gave_up[handshake ? 1 : 0], 1);
    }
    return false;
}

static __always_inline bool classification_gave_up(conn_tuple_t *tuple) {
    conn_tuple_t key;
    classification_budget_key(tuple, &key);
    classification_budget_t *budget = bpf_map_lookup_elem(&classify_budget, &key);
    return budget && (budget->flags & CLASSIFICATION_GAVE_UP);
}

static __always_inline void delete_classification_budget(conn_tuple_t *tuple) {
    conn_tuple_t key;
    classification_budget_key(tuple, &key);
    bpf_map_delete_elem(&classify_budget, &key);
}

static __always_inline protocol_stack_t* __get_protocol_stack_if_exists(conn_tuple_t* tuple) {
    protocol_stack_wrapper_t *wrapper = bpf_map_lookup_elem(&connection_protocol, tuple);
    if (!wrapper) {
        return NULL;
    }
    wrapper->updated = bpf_ktime_get_ns();
    return &wrapper->stack;
}

// Returns the protocol_stack_t associated with the given connection tuple.
// If the tuple is not found, returns NULL.
static __always_inline protocol_stack_t* get_protocol_stack_if_exists(conn_tuple_t* tuple) {
    conn_tuple_t normalized_tup = *tuple;
    normalize_tuple(&normalized_tup);
    return __get_protocol_stack_if_exists(&normalized_tup);
}

// Returns the protocol_stack_t associated with the given connection tuple.
// If the tuple is not found, creates a new entry and returns it.
static __always_inline protocol_stack_t* get_or_create_protocol_stack(conn_tuple_t *skb_tup) {
    conn_tuple_t normalized_tup = *skb_tup;
    normalize_tuple(&normalized_tup);
    protocol_stack_t *wrapper = __get_protocol_stack_if_exists(&normalized_tup);
    if (wrapper) {
        return wrapper;
    }

    // this code path is executed once during the entire connection lifecycle
    protocol_stack_wrapper_t empty_wrapper = {0};

    // We skip EEXIST because of the use of BPF_NOEXIST flag. Emitting telemetry for EEXIST here spams metrics
    // and do not provide any useful signal since the key is expected to be present sometimes.
    //
    // EBUSY can be returned if a program tries to access an already held bucket lock
    // https://elixir.bootlin.com/linux/latest/source/kernel/bpf/hashtab.c#L164
    // Before kernel version 6.7 it was possible for a program to get interrupted before disabling
    // interrupts for acquiring the bucket spinlock but after marking a bucket as busy.
    // https://github.com/torvalds/linux/commit/d35381aa73f7e1e8b25f3ed5283287a64d9ddff5
    // As such a program running from an irq context would falsely see a bucket as busy in certain cases
    // as explained in the linked commit message.
    //
    // Since connection_protocol is shared between programs running in different contexts, it gets effected by the
    // above scenario.
    // However the EBUSY error does not carry any signal for us since this is caused by a kernel bug.
    bpf_map_update_with_telemetry(connection_protocol, &normalized_tup, &empty_wrapper, BPF_NOEXIST, -EEXIST, -EBUSY);
    return __get_protocol_stack_if_exists(&normalized_tup);
}

__maybe_unused static __always_inline void update_protocol_stack(conn_tuple_t* skb_tup, protocol_t cur_fragment_protocol) {
    protocol_stack_t *stack = get_or_create_protocol_stack(skb_tup);
    if (!stack) {
        return;
    }

    set_protocol(stack, cur_fragment_protocol);
}

__maybe_unused static __always_inline void delete_protocol_stack(conn_tuple_t* normalized_tuple, protocol_stack_t *stack, u8 deletion_flag) {
    if (!normalized_tuple) {
        return;
    }

    if (!stack) {
        stack = bpf_map_lookup_elem(&connection_protocol, normalized_tuple);
        if (!stack) {
            return;
        }
    }

    if (!(stack->flags&FLAG_USM_ENABLED) || !(stack->flags&FLAG_NPM_ENABLED)) {
        // If either USM is disabled or NPM is disabled, we can move right away
        // to the deletion code since there is no chance of race between the two
        // programs.
        //
        // There are two expected scenarios where just one of the two programs
        // is enabled:
        //
        // 1) When one of the programs is disabled by choice (via configuration);
        //
        // 2) During system-probe startup: when system-probe is initializing
        // there is a short time window where the socket filter programs runs
        // alone *before* the `tcp_close` probe is activated. In a host with a
        // network-heavy workload this could easily result in thousands of
        // leaked entries.
        goto deletion;
    }

    // Otherwise we mark the protocol stack with the deletion flag
    //
    // In order to proceed with the deletion both the `tcp_close` probe and the
    // socket filter program must have reached this codepath, to ensure that
    // data is not prematurely deleted and both programs are able to handle the
    // termination path.
    //
    // Given that we're not using an atomic operation below, in the unlikely
    // event that tcp_close and the socket filter processing the FIN packet
    // execute at the same time, there is a chance that none of the callers
    // of this function will ever see both flags set.
    // We assume this is rare and OK since we're using an LRU map which will
    // eventually evict the leaked entry if it ever reaches capacity.
    //
    // Note that we could instead have a reference count field and increment it
    // attomically using the __sync_fetch_and_add builtin, which produces a
    // BPF_ATOMIC_ADD instruction. The problem is that this instruction requires
    // a 64-bit operand that would increase the size of of `protocol_stack_t` by
    // 3x. Since each `connection_tuple_t` embeds a `protocol_stack_t` that will
    // bloat the eBPF stack size for some of the tracer programs.
    //
    // In any case, even if we were using atomic operations, there is still a
    // chance of leak we can't avoid in the context of kprobe misses, so it's ok
    // to rely on the LRU in those cases.
    stack->flags |= deletion_flag;
    if (!(stack->flags&FLAG_TCP_CLOSE_DELETION) ||
        !(stack->flags&FLAG_SOCKET_FILTER_DELETION)) {
        return;
    }
 deletion:
    if (stack->flags&FLAG_SERVER_SIDE && stack->flags&FLAG_CLIENT_SIDE) {
        // If we reach this code path it means both client and server are
        // present in this host. To avoid a race condition where one side
        // potentially deletes protocol information before the other gets a
        // chance to retrieve it, we clear these flags and bail out, which
        // defers the deletion of protocol data to the last one to reach this
        // code path.
        stack->flags = stack->flags & ~(FLAG_SERVER_SIDE|FLAG_CLIENT_SIDE);
        return;
    }
    bpf_map_delete_elem(&connection_protocol, normalized_tuple);
}

#endif
