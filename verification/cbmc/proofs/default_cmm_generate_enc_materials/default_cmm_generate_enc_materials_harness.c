/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/materials.h>
#include <make_common_data_structures.h>

int on_encrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg);

void default_cmm_generate_enc_materials_harness() {
    /* Nondet input required to init cmm */
    struct aws_cryptosdk_keyring *keyring        = malloc(sizeof(*keyring));
    const struct aws_cryptosdk_keyring_vt vtable = { .vt_size    = sizeof(struct aws_cryptosdk_keyring_vt),
                                                     .name       = ensure_c_str_is_allocated(SIZE_MAX),
                                                     .destroy    = nondet_voidp(),
                                                     .on_encrypt = nondet_bool() ? NULL : on_encrypt,
                                                     .on_decrypt = nondet_voidp() };
    /* Assumptions required to init cmm */
    ensure_cryptosdk_keyring_has_allocated_members(keyring, &vtable);
    __CPROVER_assume(aws_cryptosdk_keyring_is_valid(keyring));
    __CPROVER_assume(keyring->vtable != NULL);

    /* Nondet input */
    struct aws_cryptosdk_cmm *cmm               = ensure_default_cmm_attempt_allocation(keyring);
    struct aws_cryptosdk_enc_materials **output = malloc(sizeof(*output));
    struct aws_cryptosdk_enc_request *request   = ensure_enc_request_attempt_allocation(MAX_TABLE_SIZE);

    /* Assumptions */
    __CPROVER_assume(cmm != NULL);
    __CPROVER_assume(aws_cryptosdk_default_cmm_is_valid(cmm));

    __CPROVER_assume(output != NULL);

    __CPROVER_assume(request != NULL);
    __CPROVER_assume(aws_allocator_is_valid(request->alloc));
    __CPROVER_assume(request->enc_ctx != NULL);
    __CPROVER_assume(aws_cryptosdk_enc_request_is_valid(request));

    enum aws_cryptosdk_alg_id alg_id;
    if (nondet_bool()) request->requested_alg = alg_id;
    // We can either add this OR add "if (!props) goto err;" after line 61 in the source code
    // I think adding the check to the source code is better in this case.
    // struct aws_cryptosdk_alg_properties *alg_props = aws_cryptosdk_alg_props(alg_id);
    // __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(alg_props));

    /* Nondet set self->default_alg to a valid alg_id */
    __CPROVER_assume(aws_cryptosdk_default_cmm_set_alg_id(cmm, alg_id) == AWS_OP_SUCCESS);

    /* Operation under verification */
    if (__CPROVER_file_local_default_cmm_c_default_cmm_generate_enc_materials(cmm, output, request) == AWS_OP_SUCCESS) {
        assert(aws_cryptosdk_enc_materials_is_valid(*output));
    } else {
        assert(*output == NULL);
    }

    /* Postconditions */
    assert(aws_cryptosdk_default_cmm_is_valid(cmm));
    assert(aws_cryptosdk_enc_request_is_valid(request));
}
