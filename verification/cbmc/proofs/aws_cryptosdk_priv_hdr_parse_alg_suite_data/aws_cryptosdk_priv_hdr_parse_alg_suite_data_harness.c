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
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

void aws_cryptosdk_priv_hdr_parse_alg_suite_data_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_hdr *hdr   = hdr_setup(MAX_TABLE_SIZE, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE);
    struct aws_byte_cursor *pcursor = malloc(sizeof(*pcursor));
    enum aws_cryptosdk_alg_props alg_id;
    struct aws_cryptosdk_alg_properties *alg_props = aws_cryptosdk_alg_props(alg_id);

    /* Assumptions */
    __CPROVER_assume(pcursor != NULL);
    __CPROVER_assume(aws_byte_cursor_is_bounded(pcursor, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(pcursor);
    __CPROVER_assume(aws_byte_cursor_is_valid(pcursor));

    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(alg_props));

    /* Save current state of the data structure */
    struct aws_byte_buf old_iv = hdr->iv;
    struct store_byte_from_buffer old_byte_from_iv;
    save_byte_from_array(hdr->iv.buffer, hdr->iv.len, &old_byte_from_iv);

    struct aws_byte_buf old_auth_tag = hdr->auth_tag;
    struct store_byte_from_buffer old_byte_from_auth_tag;
    save_byte_from_array(hdr->auth_tag.buffer, hdr->auth_tag.len, &old_byte_from_auth_tag);

    struct aws_byte_buf old_message_id = hdr->message_id;
    struct store_byte_from_buffer old_byte_from_message_id;
    save_byte_from_array(hdr->message_id.buffer, hdr->message_id.len, &old_byte_from_message_id);

    struct store_byte_from_buffer old_enc_ctx;
    save_byte_from_hash_table(&hdr->enc_ctx, &old_enc_ctx);

    /* Operation under verification */
    if (aws_cryptosdk_priv_hdr_parse_alg_suite_data(hdr, alg_props, pcursor) == AWS_OP_SUCCESS) {
        /* Postconditions */
        assert(aws_cryptosdk_hdr_is_valid(hdr));
        assert_byte_buf_equivalence(&hdr->iv, &old_iv, &old_byte_from_iv);
        assert_byte_buf_equivalence(&hdr->auth_tag, &old_auth_tag, &old_byte_from_auth_tag);
        assert_byte_buf_equivalence(&hdr->message_id, &old_message_id, &old_byte_from_message_id);
        check_hash_table_unchanged(&hdr->enc_ctx, &old_enc_ctx);
    }
}
