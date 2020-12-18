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

#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>
#include <cbmc_invariants.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

/**
 * A generator function as described in the comment in aws_cryptosdk_hash_elems_array_init_stub.c.
 * Also see DEFINES += -DAWS_CRYPTOSDK_HASH_ELEMS_ARRAY_INIT_GENERATOR=array_list_item_generator
 * (line 37) in the Makefile.
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

void sign_header_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_session *session = malloc(sizeof(*session));

    /* Assumptions */
    __CPROVER_assume(session != NULL);

    enum aws_cryptosdk_alg_id alg_id;
    struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);
    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(props));
    session->alg_props = props;

    struct aws_cryptosdk_hdr *hdr = hdr_setup(MAX_TABLE_SIZE, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE);
    __CPROVER_assume(IMPLIES(hdr != NULL, aws_byte_buf_is_bounded(&hdr->iv, session->alg_props->iv_len)));
    __CPROVER_assume(IMPLIES(hdr != NULL, aws_byte_buf_is_bounded(&hdr->auth_tag, session->alg_props->tag_len)));

    session->header = *hdr;

    struct aws_cryptosdk_sig_ctx *ctx = ensure_nondet_sig_ctx_has_allocated_members();
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(ctx));
    session->signctx = ctx;

    __CPROVER_assume(aws_allocator_is_valid(session->alloc));
    __CPROVER_assume(session->state == ST_GEN_KEY);
    __CPROVER_assume(session->mode == AWS_CRYPTOSDK_ENCRYPT);

    /* Save current state of the data structure */
    struct aws_byte_buf old_message_id = session->header.message_id;
    struct store_byte_from_buffer old_byte_from_message_id;
    save_byte_from_array(session->header.message_id.buffer, session->header.message_id.len, &old_byte_from_message_id);

    struct aws_byte_buf old_alg_suite_data = session->header.alg_suite_data;
    struct store_byte_from_buffer old_byte_from_alg_suite_data;
    save_byte_from_array(
        session->header.alg_suite_data.buffer, session->header.alg_suite_data.len, &old_byte_from_alg_suite_data);

    struct store_byte_from_buffer old_enc_ctx;
    save_byte_from_hash_table(&session->header.enc_ctx, &old_enc_ctx);

    /* Operation under verification */
    __CPROVER_file_local_session_encrypt_c_sign_header(session);

    /* Assertions */
    assert(aws_cryptosdk_hdr_is_valid(&session->header));
    assert_byte_buf_equivalence(&session->header.message_id, &old_message_id, &old_byte_from_message_id);
    assert_byte_buf_equivalence(&session->header.alg_suite_data, &old_alg_suite_data, &old_byte_from_alg_suite_data);
    check_hash_table_unchanged(&session->header.enc_ctx, &old_enc_ctx);
}
