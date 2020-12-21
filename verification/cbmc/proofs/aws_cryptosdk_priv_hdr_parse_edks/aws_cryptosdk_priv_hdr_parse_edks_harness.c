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

static bool flag = true;

/**
 * In the aws_cryptosdk_enc_ctx_deserialize() proof, the first value we read is the number of elements,
 * which needs to be constrained in order to ensure that the proof finishes. All other values can be left nondet.
 * This generates exactly that set of bytes
 */
uint16_t aws_byte_cursor_read_be16_generator_for_parse_edks(const struct aws_byte_cursor *cursor) {
    (void)cursor;
    uint16_t rval;
    if (flag) {
        __CPROVER_assume(rval <= MAX_EDK_LIST_ITEMS);
        flag = false;
    }
    return rval;
}

/**
 * We stub aws_array_list_push_back for performance.
 * We check that the value added to the edk_list is a valid edk, ensuring that the hdr structure remains valid.
 * Otherwise, this stub is basically a no-op and does not modify the list.
 */
int aws_array_list_push_back(struct aws_array_list *AWS_RESTRICT list, const void *val) {
    assert(aws_array_list_is_valid(list));
    assert(val && AWS_MEM_IS_READABLE(val, list->item_size));
    assert(aws_cryptosdk_edk_is_valid(val));
    if (nondet_bool()) {
        return 0;
    }
    return 1;
}

void aws_cryptosdk_priv_hdr_parse_edks_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_hdr *hdr   = hdr_setup(MAX_TABLE_SIZE, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE);
    struct aws_byte_cursor *pcursor = malloc(sizeof(*pcursor));

    /* Assumptions */
    __CPROVER_assume(pcursor != NULL);
    __CPROVER_assume(aws_byte_cursor_is_bounded(pcursor, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(pcursor);
    __CPROVER_assume(aws_byte_cursor_is_valid(pcursor));

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

    struct aws_byte_buf old_alg_suite_data = hdr->alg_suite_data;
    struct store_byte_from_buffer old_byte_from_alg_suite_data;
    save_byte_from_array(hdr->alg_suite_data.buffer, hdr->alg_suite_data.len, &old_byte_from_alg_suite_data);

    struct store_byte_from_buffer old_enc_ctx;
    save_byte_from_hash_table(&hdr->enc_ctx, &old_enc_ctx);

    /* Operation under verification */
    if (aws_cryptosdk_priv_hdr_parse_edks(hdr, pcursor) == AWS_OP_SUCCESS) {
        /* Postconditions */
        assert_byte_buf_equivalence(&hdr->iv, &old_iv, &old_byte_from_iv);
        assert_byte_buf_equivalence(&hdr->auth_tag, &old_auth_tag, &old_byte_from_auth_tag);
        assert_byte_buf_equivalence(&hdr->message_id, &old_message_id, &old_byte_from_message_id);
        assert_byte_buf_equivalence(&hdr->alg_suite_data, &old_alg_suite_data, &old_byte_from_alg_suite_data);
        check_hash_table_unchanged(&hdr->enc_ctx, &old_enc_ctx);
    }
}
