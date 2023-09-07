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
#include <proof_allocators.h>
#include <proof_helpers/utils.h>

// A generator function as described in the comment in aws_cryptosdk_hash_elems_array_init_stub.c.
// Also see line 36 of the Makefile.
void array_list_item_generator(struct aws_array_list *elems) {
    assert(elems->item_size == sizeof(struct aws_hash_element));
    for (size_t index = 0; index < elems->length; ++index) {
        struct aws_hash_element *val = (struct aws_hash_element *)((uint8_t *)elems->data + (elems->item_size * index));
        // Due to the checks in aws_cryptosdk_enc_ctx_size, no string can have a length > UINT16_MAX
        struct aws_string *key = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(key));
        __CPROVER_assume(key->len <= UINT16_MAX);
        val->key                 = key;
        struct aws_string *value = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(value));
        __CPROVER_assume(value->len <= UINT16_MAX);
        val->value = value;
    }
}

void aws_cryptosdk_enc_ctx_serialize_harness() {
    /* Nondet Input */
    struct aws_byte_buf *output = malloc(sizeof(*output));
    struct aws_hash_table *map  = malloc(sizeof(*map));

    /* Assumptions */
    ensure_byte_buf_has_allocated_buffer_member(output);
    __CPROVER_assume(aws_byte_buf_is_valid(output));
    ensure_allocated_hash_table(map, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(map));
    ensure_hash_table_has_valid_destroy_functions(map);
    size_t empty_slot_idx;
    __CPROVER_assume(aws_hash_table_has_an_empty_slot(map, &empty_slot_idx));

    /* Operation under verification */
    aws_cryptosdk_enc_ctx_serialize(can_fail_allocator(), output, map);
}
