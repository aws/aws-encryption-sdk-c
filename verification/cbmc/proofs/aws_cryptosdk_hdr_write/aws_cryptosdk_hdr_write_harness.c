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

/**
 * A generator function as described in the comment in aws_cryptosdk_hash_elems_array_init_stub.c.
 * Also see line 33 of the Makefile.
 */
void array_list_item_generator(struct aws_array_list *elems) {
    assert(elems->item_size == sizeof(struct aws_hash_element));
    for (size_t index = 0; index < elems->length; ++index) {
        struct aws_hash_element *val = (struct aws_hash_element *)((uint8_t *)elems->data + (elems->item_size * index));
        /* Due to the checks in aws_cryptosdk_enc_ctx_size, no string can have a length > UINT16_MAX. */
        struct aws_string *key = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(key));
        /* Due to the cast to uint16, the entire size of the enc_ctx must be less than < UINT16_MAX
         * This is a simple way to ensure this without a call to enc_ctx_size. */
        __CPROVER_assume(key->len <= UINT8_MAX);
        val->key                 = key;
        struct aws_string *value = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(value));
        __CPROVER_assume(value->len <= UINT8_MAX);
        val->value = value;
    }
}

void aws_cryptosdk_hdr_write_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_hdr *hdr = ensure_nondet_hdr_has_allocated_members(MAX_TABLE_SIZE);
    size_t *bytes_written;
    uint8_t *outbuf;
    size_t outlen;

    /* Assumptions */
    __CPROVER_assume(aws_cryptosdk_hdr_members_are_bounded(hdr, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE));
    __CPROVER_assume(IMPLIES(hdr != NULL, aws_byte_buf_is_bounded(&hdr->iv, MAX_IV_LEN)));

    /* Precondition: The edk list has allocated list elements */
    ensure_cryptosdk_edk_list_has_allocated_list_elements(&hdr->edk_list);
    __CPROVER_assume(aws_cryptosdk_hdr_is_valid(hdr));

    __CPROVER_assume(hdr->enc_ctx.p_impl != NULL);
    ensure_hash_table_has_valid_destroy_functions(&hdr->enc_ctx);
    size_t empty_slot_idx;
    __CPROVER_assume(aws_hash_table_has_an_empty_slot(&hdr->enc_ctx, &empty_slot_idx));

    ASSUME_VALID_MEMORY_COUNT(outbuf, outlen);
    ASSUME_VALID_MEMORY(bytes_written);

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
    aws_cryptosdk_hdr_write(hdr, bytes_written, outbuf, outlen);

    /* Assertions */
    assert(aws_cryptosdk_hdr_is_valid(hdr));
    assert_byte_buf_equivalence(&hdr->iv, &old_iv, &old_byte_from_iv);
    assert_byte_buf_equivalence(&hdr->auth_tag, &old_auth_tag, &old_byte_from_auth_tag);
    assert_byte_buf_equivalence(&hdr->message_id, &old_message_id, &old_byte_from_message_id);
    assert_byte_buf_equivalence(&hdr->alg_suite_data, &old_alg_suite_data, &old_byte_from_alg_suite_data);
    check_hash_table_unchanged(&hdr->enc_ctx, &old_enc_ctx);
}
