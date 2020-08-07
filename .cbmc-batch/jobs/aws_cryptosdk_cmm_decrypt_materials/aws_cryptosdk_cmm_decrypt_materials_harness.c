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
#include <cbmc_invariants.h>
#include <cipher_openssl.h>
#include <make_common_data_structures.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

// Stub this until https://github.com/diffblue/cbmc/issues/5344 is fixed
// Original function is here:
// https://github.com/aws/aws-encryption-sdk-c/blob/master/source/edk.c#L44
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
int decrypt_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_dec_materials **output,
    struct aws_cryptosdk_dec_request *request) {
    assert(aws_cryptosdk_cmm_base_is_valid(cmm));
    assert(AWS_OBJECT_PTR_IS_WRITABLE(output));
    assert(aws_cryptosdk_dec_request_is_valid(request));

    struct aws_cryptosdk_dec_materials *materials = can_fail_malloc(sizeof(*materials));
    if (materials == NULL) {
        *output = NULL;
        return AWS_OP_ERR;
    }

    // Set up the allocator
    materials->alloc = request->alloc;
    __CPROVER_assume(aws_allocator_is_valid(materials->alloc));

    // Set up the unencrypted_data_key
    __CPROVER_assume(aws_byte_buf_is_bounded(&materials->unencrypted_data_key, MAX_NUM_ITEMS));
    ensure_byte_buf_has_allocated_buffer_member(&materials->unencrypted_data_key);
    __CPROVER_assume(aws_byte_buf_is_valid(&materials->unencrypted_data_key));

    // Set up the signctx
    materials->signctx = can_fail_malloc(sizeof(*materials->signctx));
    if (materials->signctx) {
        ensure_sig_ctx_has_allocated_members(materials->signctx);
        __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(materials->signctx));
    }

    *output = materials;
    return AWS_OP_SUCCESS;
}

void aws_cryptosdk_cmm_decrypt_materials_harness() {
    const struct aws_cryptosdk_cmm_vt vtable = { .vt_size                = sizeof(struct aws_cryptosdk_cmm_vt),
                                                 .name                   = ensure_c_str_is_allocated(SIZE_MAX),
                                                 .destroy                = nondet_voidp(),
                                                 .generate_enc_materials = nondet_voidp(),
                                                 .decrypt_materials      = nondet_bool() ? decrypt_materials : NULL };
    __CPROVER_assume(aws_cryptosdk_cmm_vtable_is_valid(&vtable));

    struct aws_cryptosdk_cmm *cmm = can_fail_malloc(sizeof(*cmm));
    __CPROVER_assume(cmm);
    cmm->vtable = &vtable;
    __CPROVER_assume(aws_cryptosdk_cmm_base_is_valid(cmm));

    struct aws_cryptosdk_dec_request *request = can_fail_malloc(sizeof(*request));
    __CPROVER_assume(request);
    request->alloc   = can_fail_allocator();
    request->enc_ctx = can_fail_malloc(sizeof(*request->enc_ctx));
    __CPROVER_assume(request->enc_ctx);
    ensure_allocated_hash_table(request->enc_ctx, MAX_NUM_ITEMS);

    // Setup the edk_list in the request
    // Set up the edk_list
    // edk_list Precondition: We have a valid list
    __CPROVER_assume(aws_cryptosdk_edk_list_is_bounded(&request->encrypted_data_keys, MAX_NUM_ITEMS));
    ensure_cryptosdk_edk_list_has_allocated_list(&request->encrypted_data_keys);
    __CPROVER_assume(aws_cryptosdk_edk_list_is_valid(&request->encrypted_data_keys));

    // Stub until https://github.com/diffblue/cbmc/issues/5344 is fixed
    // edk_list Precondition: The list has valid list elements
    /*
      __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_bounded(&request->encrypted_data_keys, MAX_STRING_LEN));
      ensure_cryptosdk_edk_list_has_allocated_list_elements(&request->encrypted_data_keys);
      __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_valid(&request->encrypted_data_keys));
    */
    __CPROVER_assume(aws_cryptosdk_dec_request_is_valid(request));

    struct aws_cryptosdk_enc_materials **output = can_fail_malloc(sizeof(*output));
    __CPROVER_assume(output);

    // Run the function under test.
    if (aws_cryptosdk_cmm_decrypt_materials(cmm, output, request) == AWS_OP_SUCCESS) {
        assert(aws_cryptosdk_dec_materials_is_valid(*output));
    } else {
        assert(*output == NULL);
    }

    assert(aws_cryptosdk_cmm_base_is_valid(cmm));
    assert(aws_cryptosdk_dec_request_is_valid(request));
}
