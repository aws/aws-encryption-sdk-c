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

#include <aws/common/string.h>
#include <aws/common/array_list.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/utils.h>
#include <aws/cryptosdk/private/utils.h>

void aws_cryptosdk_string_dup_harness() {
    /* data structure */
    struct aws_allocator *alloc = can_fail_allocator(); /* Precondition: alloc must be non-null */
    struct aws_string *str_a = ensure_string_is_allocated_bounded_length(MAX_STRING_LEN);

    struct aws_string *str_b = aws_cryptosdk_string_dup(alloc, str_a);
    /* assertions */ 
    aws_string_eq(str_a, str_b);

}
