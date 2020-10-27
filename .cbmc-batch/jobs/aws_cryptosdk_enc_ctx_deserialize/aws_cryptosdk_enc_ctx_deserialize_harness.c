/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

void make_hash_table_with_no_backing_store(struct aws_hash_table *map, size_t max_table_entries);

/**
 * In the aws_cryptosdk_enc_ctx_deserilize() proof, the first value we read is the number of elements,
 * which we need to be constrained in order to ensure that the proof finishes. All other values can be left nondet.
 * This generates exactly that set of bytes
 */
uint16_t aws_byte_cursor_read_be16_generator_for_enc_ctx_deserialize(const struct aws_byte_cursor *cursor) {
    (void)cursor;
    static int num_times_called = 0;
    num_times_called++;
    uint16_t rval;
    if (num_times_called == 1) {
        __CPROVER_assume(rval <= MAX_NUM_ELEMS);
    }
    return rval;
}

/**
 * The actual proof
 */
void aws_cryptosdk_enc_ctx_deserialize_harness() {
    /* Nondet Input */
    struct aws_byte_cursor *cursor = malloc(sizeof(*cursor));
    struct aws_hash_table *map     = malloc(sizeof(*map));

    /* Assumptions */
    ensure_byte_cursor_has_allocated_buffer_member(cursor);
    __CPROVER_assume(aws_byte_cursor_is_valid(cursor));

    /* the number of elements is stored in big endian format */
    if (cursor->len >= 2) {
        cursor->ptr[0] = 0;
        cursor->ptr[1] = MAX_NUM_ELEMS;
    }

    ensure_allocated_hash_table(map, SIZE_MAX);
    make_hash_table_with_no_backing_store(map, SIZE_MAX);
    __CPROVER_assume(aws_hash_table_is_valid(map));

    /* Function under verification */
    int rval = aws_cryptosdk_enc_ctx_deserialize(can_fail_allocator(), map, cursor);

    /* Post-conditions */
    assert(aws_hash_table_is_valid(map));
    assert(aws_byte_cursor_is_valid(cursor));
}
