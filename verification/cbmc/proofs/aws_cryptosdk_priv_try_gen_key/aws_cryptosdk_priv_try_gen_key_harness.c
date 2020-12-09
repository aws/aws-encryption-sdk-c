/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/keyring_trace.h>
#include <cbmc_invariants.h>
#include <cipher_openssl.h>
#include <make_common_data_structures.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/hkdf.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>

/* Stub this for performance but check the preconditions.
 No modified data structure is used again.
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/hkdf.c#148 */
int aws_cryptosdk_hkdf(
    struct aws_byte_buf *okm,
    enum aws_cryptosdk_sha_version which_sha,
    const struct aws_byte_buf *salt,
    const struct aws_byte_buf *ikm,
    const struct aws_byte_buf *info) {
    assert(aws_byte_buf_is_valid(salt));
    assert(aws_byte_buf_is_valid(ikm));
    assert(aws_byte_buf_is_valid(info));
    if (nondet_bool()) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

/* Stub this because of the override of aws_array_list_get_at_ptr and for performance.
 The contents of session_>keyring_trace are nondet in the construction of the harness.
 Also neither keyring trace is later used.
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/list_utils.c#L17 */
int aws_cryptosdk_transfer_list(struct aws_array_list *dest, struct aws_array_list *src) {
    assert(src != dest);
    assert(aws_array_list_is_valid(dest));
    assert(aws_array_list_is_valid(src));
    assert(dest->item_size == src->item_size);

    if (nondet_bool()) {
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

void array_list_item_generator(struct aws_array_list *elems) {
    assert(elems->item_size == sizeof(struct aws_hash_element));
    for (size_t index = 0; index < elems->length; ++index) {
        struct aws_hash_element *val = (struct aws_hash_element *)((uint8_t *)elems->data + (elems->item_size * index));
        /* Due to the cast to uint16, the entire size of the enc_ctx must be less than < UINT16_MAX
         * This is a simple way to ensure this without a call to enc_ctx_size. */
        struct aws_string *key = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(key));
        __CPROVER_assume(key->len <= UINT8_MAX);
        val->key                 = key;
        struct aws_string *value = ensure_string_is_allocated_nondet_length();
        __CPROVER_assume(aws_string_is_valid(value));
        __CPROVER_assume(value->len <= UINT8_MAX);
        val->value = value;
    }
}

/* Stub this because of the override of aws_array_list_get_at_ptr
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/keyring_trace.c#L235 */
void aws_cryptosdk_keyring_trace_clear(struct aws_array_list *trace) {
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    AWS_FATAL_PRECONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    aws_array_list_clear(trace);
}

/* Stub this until https://github.com/diffblue/cbmc/issues/5344 is fixed
 Original function is here:
 https://github.com/aws/aws-encryption-sdk-c/blob/master/source/edk.c#L44 */
void aws_cryptosdk_edk_list_clean_up(struct aws_array_list *encrypted_data_keys) {
    assert(aws_cryptosdk_edk_list_is_valid(encrypted_data_keys));
    aws_array_list_clean_up(encrypted_data_keys);
}

/**
 * Receives encryption request from user and attempts to generate encryption materials,
 * including an encrypted data key and a list of EDKs for doing encryption.
 *
 * On success returns AWS_OP_SUCCESS and allocates encryption materials object at address
 * pointed to by output.
 *
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets
 * internal AWS error code.
 */
int generate_enc_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_enc_materials **output,
    struct aws_cryptosdk_enc_request *request) {
    assert(aws_cryptosdk_cmm_base_is_valid(cmm));
    assert(AWS_OBJECT_PTR_IS_WRITABLE(output));
    assert(aws_cryptosdk_enc_request_is_valid(request));

    struct aws_cryptosdk_enc_materials *materials = malloc(sizeof(*materials));
    if (materials == NULL) {
        *output = NULL;
        return AWS_OP_ERR;
    }

    // Set up the allocator
    // Request->alloc is session->alloc
    materials->alloc = request->alloc;
    __CPROVER_assume(aws_allocator_is_valid(materials->alloc));
    __CPROVER_assume(materials->alloc != NULL);

    // Set up the signctx
    materials->signctx = ensure_nondet_sig_ctx_has_allocated_members();
    __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(materials->signctx));

    // Set up the unencrypted_data_key
    __CPROVER_assume(aws_byte_buf_is_bounded(&materials->unencrypted_data_key, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&materials->unencrypted_data_key);
    __CPROVER_assume(aws_byte_buf_is_valid(&materials->unencrypted_data_key));

    // Set up the edk_list
    // edk_list Precondition: We have a valid list */
    __CPROVER_assume(aws_cryptosdk_edk_list_is_bounded(&materials->encrypted_data_keys, MAX_EDK_LIST_ITEMS));
    ensure_cryptosdk_edk_list_has_allocated_list(&materials->encrypted_data_keys);
    __CPROVER_assume(aws_cryptosdk_edk_list_is_valid(&materials->encrypted_data_keys));

    // The alloc is session->alloc
    materials->encrypted_data_keys.alloc = request->alloc;

    // edk_list Precondition: The list has valid list elements
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_bounded(&materials->encrypted_data_keys, MAX_BUFFER_SIZE));
    ensure_cryptosdk_edk_list_has_allocated_list_elements(&materials->encrypted_data_keys);
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_valid(&materials->encrypted_data_keys));

    // Set up the keyring trace
    __CPROVER_assume(aws_array_list_is_bounded(
        &materials->keyring_trace, MAX_TRACE_NUM_ITEMS, sizeof(struct aws_cryptosdk_keyring_trace_record)));
    __CPROVER_assume(materials->keyring_trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&materials->keyring_trace);
    __CPROVER_assume(aws_array_list_is_valid(&materials->keyring_trace));
    ensure_trace_has_allocated_records(&materials->keyring_trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&materials->keyring_trace));

    // Set the alg_id
    enum aws_cryptosdk_alg_id alg_id;
    materials->alg = alg_id;

    *output = materials;
    return AWS_OP_SUCCESS;
}

void aws_cryptosdk_priv_try_gen_key_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_session *session = malloc(sizeof(*session));

    /* Assumptions */
    __CPROVER_assume(session != NULL);

    const struct aws_cryptosdk_cmm_vt vtable = { .vt_size = sizeof(struct aws_cryptosdk_cmm_vt),
                                                 .name    = ensure_c_str_is_allocated(SIZE_MAX),
                                                 .destroy = nondet_voidp(),
                                                 .generate_enc_materials =
                                                     nondet_bool() ? generate_enc_materials : NULL,
                                                 .decrypt_materials = nondet_voidp() };
    __CPROVER_assume(aws_cryptosdk_cmm_vtable_is_valid(&vtable));

    struct aws_cryptosdk_cmm *cmm = malloc(sizeof(*cmm));
    __CPROVER_assume(cmm);
    cmm->vtable = &vtable;
    __CPROVER_assume(aws_cryptosdk_cmm_base_is_valid(cmm));
    session->cmm = cmm;

    enum aws_cryptosdk_alg_id alg_id;
    struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);
    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(props));
    session->alg_props = props;

    struct aws_cryptosdk_hdr *hdr = ensure_nondet_hdr_has_allocated_members(MAX_TABLE_SIZE);

    __CPROVER_assume(aws_cryptosdk_hdr_members_are_bounded(hdr, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE));

    __CPROVER_assume(IMPLIES(hdr != NULL, aws_byte_buf_is_bounded(&hdr->iv, session->alg_props->iv_len)));
    __CPROVER_assume(IMPLIES(hdr != NULL, aws_byte_buf_is_bounded(&hdr->auth_tag, session->alg_props->tag_len)));

    ensure_cryptosdk_edk_list_has_allocated_list_elements(&hdr->edk_list);

    __CPROVER_assume(aws_cryptosdk_hdr_is_valid(hdr));

    // The header should have been cleared earlier
    __CPROVER_assume(aws_array_list_length(&hdr->edk_list) == 0);

    __CPROVER_assume(hdr->enc_ctx.p_impl != NULL);
    ensure_hash_table_has_valid_destroy_functions(&hdr->enc_ctx);
    size_t empty_slot_idx;
    __CPROVER_assume(aws_hash_table_has_an_empty_slot(&hdr->enc_ctx, &empty_slot_idx));
    session->header = *hdr;

    struct aws_array_list *keyring_trace = malloc(sizeof(*keyring_trace));
    __CPROVER_assume(keyring_trace != NULL);
    __CPROVER_assume(aws_array_list_is_bounded(
        keyring_trace, MAX_TRACE_NUM_ITEMS, sizeof(struct aws_cryptosdk_keyring_trace_record)));
    __CPROVER_assume(keyring_trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(keyring_trace);
    __CPROVER_assume(aws_array_list_is_valid(keyring_trace));
    ensure_trace_has_allocated_records(keyring_trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(keyring_trace));
    session->keyring_trace = *keyring_trace;

    session->alloc = can_fail_allocator();
    __CPROVER_assume(aws_allocator_is_valid(session->alloc));
    __CPROVER_assume(session->alloc != NULL);
    session->header.edk_list.alloc = session->alloc;  // this assumption is needed for build_header
    __CPROVER_assume(aws_cryptosdk_commitment_policy_is_valid(session->commitment_policy));

    __CPROVER_assume(session->state == ST_GEN_KEY);
    __CPROVER_assume(session->mode == AWS_CRYPTOSDK_ENCRYPT);

    struct content_key *content_key = malloc(sizeof(*content_key));
    __CPROVER_assume(content_key != NULL);
    session->content_key = *content_key;

    /* Function under verification */
    aws_cryptosdk_priv_try_gen_key(session);
}
