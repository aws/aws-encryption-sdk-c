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

#include <aws/common/hash_table.h>
#include <aws/common/private/hash_table_impl.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

/**
 * Prove the aws_cryptosdk_enc_ctx_clean_up function for the case
 * where the map has an implentation.  The case where the map.p_impl is
 * null is handled by a seperate proof.
 * Ideally, these would be one proof, but __CPROVER_allocated_memory() only
 * makes sense for non-null hash-table implementations, and CBMC
 * doesn't work well with __CPROVER_allocated_memory() inside a conditional
 */
void aws_cryptosdk_enc_ctx_clean_up_harness() {
    struct aws_hash_table map;
    ensure_allocated_hash_table(&map, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(&map));
    ensure_hash_table_has_valid_destroy_functions(&map);
    map.p_impl->alloc = can_fail_allocator();

    struct hash_table_state *state = map.p_impl;
    size_t empty_slot_idx;
    size_t size_in_bytes = sizeof(struct hash_table_state) + sizeof(struct hash_table_entry) * state->size;
    __CPROVER_allocated_memory(state, size_in_bytes);  // tell CBMC to keep the buffer live after the free

    __CPROVER_assume(aws_hash_table_has_an_empty_slot(&map, &empty_slot_idx));
    aws_cryptosdk_enc_ctx_clean_up(&map);
    assert(map.p_impl == NULL);
    assert_all_zeroes(&state->slots[0], state->size * sizeof(state->slots[0]));
}
