/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/private/keyring_trace.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

void aws_cryptosdk_keyring_trace_eq_harness() {
    /* data structure */
    struct aws_array_list lhs;
    struct aws_array_list rhs;

    /* assumptions */
    __CPROVER_assume(aws_array_list_is_bounded(&lhs, MAX_INITIAL_ITEM_ALLOCATION, MAX_ITEM_SIZE));
    __CPROVER_assume(lhs.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&lhs);
    __CPROVER_assume(aws_array_list_is_valid(&lhs));
    ensure_trace_has_allocated_records(&lhs, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&lhs));

    __CPROVER_assume(aws_array_list_is_bounded(&rhs, MAX_INITIAL_ITEM_ALLOCATION, MAX_ITEM_SIZE));
    __CPROVER_assume(rhs.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&rhs);
    __CPROVER_assume(aws_array_list_is_valid(&rhs));
    ensure_trace_has_allocated_records(&rhs, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&rhs));

    /* save current state of the data structure */
    struct aws_array_list old_lhs = lhs;
    struct store_byte_from_buffer old_byte_from_lhs;
    save_byte_from_array((uint8_t *)lhs.data, lhs.current_size, &old_byte_from_lhs);
    struct aws_array_list old_rhs = rhs;
    struct store_byte_from_buffer old_byte_from_rhs;
    save_byte_from_array((uint8_t *)rhs.data, rhs.current_size, &old_byte_from_rhs);

    if (aws_cryptosdk_keyring_trace_eq(&lhs, &rhs)) {
        /* assertions */
        assert(lhs.length == rhs.length);
        size_t num_records = aws_array_list_length(&lhs);
        size_t idx;
        __CPROVER_assume(idx < num_records);
        struct aws_cryptosdk_keyring_trace_record *lhs_rec;
        struct aws_cryptosdk_keyring_trace_record *rhs_rec;
        aws_array_list_get_at_ptr(&lhs, (void **)&lhs_rec, idx);
        aws_array_list_get_at_ptr(&rhs, (void **)&rhs_rec, idx);
        assert(aws_string_eq(lhs_rec->wrapping_key_namespace, rhs_rec->wrapping_key_namespace));
        assert(aws_string_eq(lhs_rec->wrapping_key_name, rhs_rec->wrapping_key_name));
        assert(lhs_rec->flags == rhs_rec->flags);
    }
    /* assertions */
    assert(aws_array_list_is_valid(&lhs));
    assert(aws_array_list_is_valid(&rhs));
    assert_array_list_equivalence(&lhs, &old_lhs, &old_byte_from_lhs);
    assert_array_list_equivalence(&rhs, &old_rhs, &old_byte_from_rhs);
}
