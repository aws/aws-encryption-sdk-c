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

#include <aws/common/array_list.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/keyring_trace.h>
#include <aws/cryptosdk/private/keyring_trace.h>
#include <aws/cryptosdk/private/utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_keyring_trace_add_record_harness() {
    /* data structure */
    struct aws_allocator *alloc = can_fail_allocator(); /* Precondition: alloc must be non-null */
    struct aws_array_list trace;                        /* Precondition: trace must be non-null */
    struct aws_string *namespace =
        ensure_string_is_allocated_bounded_length(MAX_STRING_LEN); /* Precondition: namespace must be non-null */
    struct aws_string *name =
        ensure_string_is_allocated_bounded_length(MAX_STRING_LEN); /* Precondition: name must be non-null */
    uint32_t flags;

    __CPROVER_assume(aws_array_list_is_bounded(&trace, MAX_INITIAL_ITEM_ALLOCATION, MAX_ITEM_SIZE));
    __CPROVER_assume(trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&trace);
    __CPROVER_assume(aws_array_list_is_valid(&trace));
    ensure_trace_has_allocated_records(&trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&trace));

    struct aws_array_list old = trace;
    struct store_byte_from_buffer old_byte;
    save_byte_from_array((uint8_t *)trace.data, trace.current_size, &old_byte);

    if (aws_cryptosdk_keyring_trace_add_record(alloc, &trace, namespace, name, flags) == AWS_OP_SUCCESS) {
        /* assertions */
        assert(aws_cryptosdk_keyring_trace_is_valid(&trace));
        assert(trace.length = old.length + 1);
    } else {
        /* assertions */
        assert_array_list_equivalence(&trace, &old, &old_byte);
    }
}
