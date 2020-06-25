/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/common/hash_table.h>
#include <aws/common/private/hash_table_impl.h>
#include <aws/common/string.h>

#include <aws/cryptosdk/private/utils.h>

#include <make_common_data_structures.h>

#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_hash_elems_array_init_harness() {
    /* Non-deterministic inputs. */
    struct aws_allocator *alloc = nondet_bool() ? NULL : can_fail_allocator();
    __CPROVER_assume(aws_allocator_is_valid(alloc));

    struct aws_array_list *list = can_fail_malloc(sizeof(*list));
    __CPROVER_assume(list != NULL);

    struct aws_hash_table *map = can_fail_malloc(sizeof(*map));
    __CPROVER_assume(map != NULL);
    ensure_allocated_hash_table(map, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(map));

    /* Operation under verification. */
    if (aws_cryptosdk_hash_elems_array_init(alloc, list, map) == AWS_OP_SUCCESS) {
        /* Post-conditions. */
        assert(aws_hash_table_is_valid(map));
        assert(aws_array_list_is_valid(list));
    }
}
