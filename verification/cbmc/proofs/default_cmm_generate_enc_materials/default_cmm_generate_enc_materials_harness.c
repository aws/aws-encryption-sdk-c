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
    const struct aws_cryptosdk_keyring_vt vtable = { .vt_size    = nondet_size_t(),
                                                     .name       = ensure_c_str_is_allocated(SIZE_MAX),
                                                     .destroy    = nondet_voidp(),
                                                     .on_encrypt = nondet_bool() ? NULL : on_encrypt,
                                                     .on_decrypt = nondet_voidp() };
    /* Nondet input */
    struct aws_cryptosdk_cmm *cmm              = ensure_default_cmm_attempt_allocation(&vtable);
    struct aws_cryptosdk_enc_materials *output = ensure_enc_materials_attempt_allocation();
    struct aws_cryptosdk_enc_request *request  = ensure_enc_request_attempt_allocation(MAX_TABLE_SIZE);

    /* Assumptions */
    __CPROVER_assume(cmm != NULL);
    __CPROVER_assume(aws_cryptosdk_default_cmm_is_valid(cmm));

    __CPROVER_assume(output != NULL);

    __CPROVER_assume(request != NULL);
    __CPROVER_assume(aws_allocator_is_valid(request->alloc));
    __CPROVER_assume(request->enc_ctx != NULL);
    __CPROVER_assume(aws_cryptosdk_enc_request_is_valid(request));

    /* Save current state of the data structures */
    struct store_byte_from_buffer old_output;
    save_byte_from_array((uint8_t *)output, sizeof(*output), &old_output);

    /* Operation under verification */
    if (__CPROVER_file_local_default_cmm_c_default_cmm_generate_enc_materials(cmm, &output, request) ==
        AWS_OP_SUCCESS) {
        assert(aws_cryptosdk_enc_materials_is_valid(output));
        assert(aws_cryptosdk_algorithm_is_known(request->requested_alg));
    } else {
        /* Note that we perform a top-level comparison here */
        assert_byte_from_buffer_matches((uint8_t *)output, &old_output);
    }

    /* Postconditions */
    assert(aws_cryptosdk_default_cmm_is_valid(cmm));
    assert(aws_cryptosdk_enc_request_is_valid(request));
}
