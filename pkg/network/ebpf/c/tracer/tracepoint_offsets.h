#ifndef __TRACEPOINT_OFFSETS_H
#define __TRACEPOINT_OFFSETS_H

#include "compiler.h"

static __always_inline __u64 offset_net_dev_queue_skb() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_net_dev_queue_skb", val);
    return val;
}

static __always_inline struct sk_buff* sk_buff_from_net_dev_queue_ctx(char *ctx) {
    struct sk_buff* sk_buff = 0;
    __u64 offset_val = offset_net_dev_queue_skb();

    /* Why does this code look like it does? Reading from the context pointer can only be done through
    static offset, and the pointer is not allowed to be manipulated (ebpf verifier will bark in these cases).
    For this reason we match the offset values and then read the offset statically. We use asm to avoid the
    compiler 'optimizing' the access and turning it into illegal operations.
    In case we find more offset vals this can exist, we should add more cases.

    Technique from here: https://mejedi.dev/posts/ebpf-dereference-of-modified-ctx-ptr-disallowed/
    */
    if (offset_val == 8) {
      asm("%[res] = *(u64 *)(%[base] + %[offset])"
         : [res]"=r"(sk_buff)
         : [base]"r"(ctx), [offset]"i"(8), "m"(*ctx));
    } else if (offset_val == 16) {
      asm("%[res] = *(u64 *)(%[base] + %[offset])"
               : [res]"=r"(sk_buff)
               : [base]"r"(ctx), [offset]"i"(16), "m"(*ctx));
    }
    return sk_buff;
}

#endif
