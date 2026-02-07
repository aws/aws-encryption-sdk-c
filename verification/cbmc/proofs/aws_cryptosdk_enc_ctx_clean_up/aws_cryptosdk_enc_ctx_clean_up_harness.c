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
#include <proof_helpers/utils.h>

/*
 * Prove the aws_cryptosdk_enc_ctx_clean_up function for the cases
 * where the map both does and does not have an implementation.
 */
void aws_cryptosdk_enc_ctx_clean_up_harness() {
    struct aws_hash_table map;
    bool impl_is_null;
    ensure_allocated_hash_table(&map, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(&map));
    ensure_hash_table_has_valid_destroy_functions(&map);
    map.p_impl->alloc = aws_default_allocator();

    struct hash_table_state *state = map.p_impl;
    size_t empty_slot_idx;
    size_t size_in_bytes = sizeof(struct hash_table_state) + sizeof(struct hash_table_entry) * state->size;

    __CPROVER_assume(aws_hash_table_has_an_empty_slot(&map, &empty_slot_idx));
    if (impl_is_null) {
        map.p_impl = NULL;
    }
    aws_cryptosdk_enc_ctx_clean_up(&map);
    assert(map.p_impl == NULL);

/*
 * These pragmas disable the dereferenced object check so that
 * we can prove the previously allocated memory was zeroed
 * before it was freed. This check is re-enabled afterwards.
 */
#pragma CPROVER check push
#pragma CPROVER check disable "pointer"
    if (map.p_impl != NULL && state->size * sizeof(state->slots[0]) > 0 && &state->slots[0] != NULL) {
        size_t i;
        __CPROVER_assume(i < state->size * sizeof(state->slots[0]));
        assert(((const uint8_t *const)(&state->slots[0]))[i] == 0);
    }
#pragma CPROVER check pop
}
