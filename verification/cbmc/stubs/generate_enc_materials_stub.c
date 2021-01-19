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

#include <aws/cryptosdk/materials.h>

#include <cbmc_invariants.h>
#include <make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

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
    __CPROVER_assume(aws_cryptosdk_edk_list_is_bounded(&materials->encrypted_data_keys, MAX_EDK_LIST_ITEMS));
    ensure_cryptosdk_edk_list_has_allocated_list(&materials->encrypted_data_keys);
    __CPROVER_assume(aws_cryptosdk_edk_list_is_valid(&materials->encrypted_data_keys));

    // The alloc is session->alloc
    materials->encrypted_data_keys.alloc = request->alloc;

    // Precondition: The edk_list has valid list elements
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_bounded(&materials->encrypted_data_keys, MAX_BUFFER_SIZE));
    ensure_cryptosdk_edk_list_has_allocated_list_elements(&materials->encrypted_data_keys);
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_valid(&materials->encrypted_data_keys));

    // Set up the keyring trace
    __CPROVER_assume(aws_array_list_is_bounded(
        &materials->keyring_trace, MAX_TRACE_LIST_ITEMS, sizeof(struct aws_cryptosdk_keyring_trace_record)));
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
