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

void aws_cryptosdk_keyring_trace_clear_harness() {
    /* data structure */
    struct aws_array_list trace;

    /* assumptions */
    __CPROVER_assume(aws_array_list_is_bounded(&trace, MAX_INITIAL_ITEM_ALLOCATION, MAX_ITEM_SIZE));
    __CPROVER_assume(trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&trace);
    __CPROVER_assume(aws_array_list_is_valid(&trace));
    ensure_trace_has_allocated_records(&trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&trace));

    /* save current state of the data structure */
    struct aws_array_list old = trace;

    aws_cryptosdk_keyring_trace_clear(&trace);

    /* assertions */
    assert(aws_array_list_is_valid(&trace));
    assert(trace.length == 0);
    assert(trace.alloc == old.alloc);
    assert(trace.current_size == old.current_size);
    assert(trace.item_size == old.item_size);
    assert(trace.data == old.data);
}
