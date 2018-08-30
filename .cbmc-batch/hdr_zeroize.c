/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
