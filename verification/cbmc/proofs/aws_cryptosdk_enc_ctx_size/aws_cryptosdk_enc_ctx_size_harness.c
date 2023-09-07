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

void hash_iterator_generator(struct aws_hash_iter *new_iter, const struct aws_hash_iter *old_iter) {
    (void)old_iter;
    if (new_iter->status == AWS_HASH_ITER_STATUS_READY_FOR_USE) {
        new_iter->element.key   = ensure_string_is_allocated_nondet_length();
        new_iter->element.value = ensure_string_is_allocated_nondet_length();
    }
}

void hash_iterator_generator2(struct aws_hash_iter *new_iter, const struct aws_hash_iter *old_iter) {
    (void)old_iter;
    if (new_iter->status == AWS_HASH_ITER_STATUS_READY_FOR_USE) {
        new_iter->element.key = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(new_iter->element.key));
        new_iter->element.value = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(new_iter->element.value));
    }
}

void aws_cryptosdk_enc_ctx_size_harness() {
    /* Nondet Input */
    struct aws_hash_table *map = malloc(sizeof(*map));
    size_t *size               = malloc(sizeof(*size));

    /* Assumptions */
    __CPROVER_assume(map != NULL);
    ensure_allocated_hash_table(map, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(map));
    ensure_hash_table_has_valid_destroy_functions(map);
    size_t empty_slot_idx;
    __CPROVER_assume(aws_hash_table_has_an_empty_slot(map, &empty_slot_idx));
    __CPROVER_assume(size != NULL);

    /* Operation under verification */
    int rval = aws_cryptosdk_enc_ctx_size(size, map);

    /* Post-conditions */
    assert(aws_hash_table_is_valid(map));
}
