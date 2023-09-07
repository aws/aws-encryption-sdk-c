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
#include <proof_allocators.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_enc_ctx_clone_harness() {
    /* Nondet Input */
    struct aws_hash_table *dest = malloc(sizeof(*dest));
    struct aws_hash_table *src  = malloc(sizeof(*src));

    /* Assumptions */
    ensure_allocated_hash_table(dest, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(dest));
    __CPROVER_assume(dest->p_impl->entry_count <= MAX_TABLE_SIZE);
    ensure_hash_table_has_valid_destroy_functions(dest);

    ensure_allocated_hash_table(src, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(src));
    __CPROVER_assume(src->p_impl->entry_count <= MAX_TABLE_SIZE);
    ensure_hash_table_has_valid_destroy_functions(src);

    /* Operation under verification */
    int rval = aws_cryptosdk_enc_ctx_clone(can_fail_allocator(), dest, src);
}
