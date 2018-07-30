#include<stdlib.h>
#include<../source/header.c>

static inline void hdr_zeroize_verify(struct aws_cryptosdk_hdr *hdr) {
    // Assume hdr is allocated
    hdr = malloc(sizeof(*hdr));

    // Call function
    hdr_zeroize(hdr);

    // Ensure that all fields in header are 0 now
    assert(hdr->alg_id == 0);
    assert(hdr->aad_count == 0);
    assert(hdr->edk_count == 0);
    assert(hdr->frame_len == 0);
    assert(!hdr->iv.allocator);
    assert(!hdr->iv.buffer);
    assert(hdr->iv.len == 0);
    assert(hdr->iv.capacity == 0);
    assert(!hdr->auth_tag.allocator);
    assert(!hdr->auth_tag.buffer);
    assert(hdr->auth_tag.len == 0);
    assert(hdr->auth_tag.capacity == 0);
    // Get nondeterministic valid index
    size_t index = nondet_size_t();
    __CPROVER_assume(index < MESSAGE_ID_LEN);
    // Check message id is zero at the index
    assert(hdr->message_id[index]==0);
    assert(!hdr->aad_tbl);
    assert(!hdr->edk_tbl);
    assert(hdr->auth_len == 0);
}
