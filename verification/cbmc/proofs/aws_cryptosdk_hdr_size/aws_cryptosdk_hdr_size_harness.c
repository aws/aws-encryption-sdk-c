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

#include <aws/cryptosdk/header.h>
#include <aws/cryptosdk/private/header.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

void aws_cryptosdk_hdr_size_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_hdr *hdr = ensure_nondet_hdr_has_allocated_members(MAX_TABLE_SIZE);

    /* Assumptions */
    __CPROVER_assume(aws_cryptosdk_hdr_members_are_bounded(hdr, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE));

    /* Precondition: The edk list has allocated list elements */
    ensure_cryptosdk_edk_list_has_allocated_list_elements(&hdr->edk_list);
    __CPROVER_assume(aws_cryptosdk_hdr_is_valid(hdr));

    __CPROVER_assume(hdr->enc_ctx.p_impl != NULL);
    ensure_hash_table_has_valid_destroy_functions(&hdr->enc_ctx);
    size_t empty_slot_idx;
    __CPROVER_assume(aws_hash_table_has_an_empty_slot(&hdr->enc_ctx, &empty_slot_idx));

    /* Operation under verification */
    aws_cryptosdk_hdr_size(hdr);

    /* Postconditions */
    assert(aws_cryptosdk_hdr_is_valid(hdr));
}
