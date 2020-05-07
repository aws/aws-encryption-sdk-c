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

/*
 * Expected Runtime: 2 minutes, 30 seconds
 * Expected Coverage: 88%
 */

#include <aws/cryptosdk/private/keyring_trace.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

void aws_cryptosdk_keyring_trace_clean_up_harness() {
    /* data structure */
    struct aws_array_list trace;

    /* assumptions */
    __CPROVER_assume(
        aws_array_list_is_bounded(&trace, MAX_ITEM_SIZE, sizeof(struct aws_cryptosdk_keyring_trace_record)));
    __CPROVER_assume(trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&trace);
    __CPROVER_assume(aws_array_list_is_valid(&trace));
    ensure_trace_has_allocated_records(&trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&trace));

    aws_cryptosdk_keyring_trace_clean_up(&trace);

    /* assertions */
    assert(trace.length == 0);
}
