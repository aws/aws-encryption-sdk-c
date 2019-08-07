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
#include <aws/cryptosdk/keyring_trace.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

void aws_cryptosdk_keyring_trace_init_harness() {
    /* data structure */
    struct aws_allocator *alloc = can_fail_allocator(); /* Precondition: alloc must be non-null */
    struct aws_array_list trace; /* Precondition: trace must be non-null */

    if (aws_cryptosdk_keyring_trace_init(alloc, &trace) == AWS_OP_SUCCESS){
        /* assertions */
        assert(aws_array_list_is_valid(&trace));
        assert(trace.alloc == alloc);
        assert(trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
        assert(trace.length == 0);
    }


}
