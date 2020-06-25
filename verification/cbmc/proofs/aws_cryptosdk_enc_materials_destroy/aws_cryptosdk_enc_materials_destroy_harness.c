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

// Stub this until https://github.com/diffblue/cbmc/issues/5344 is fixed
// Original function is here:
// https://github.com/aws/aws-encryption-sdk-c/blob/master/source/edk.c#L44
void aws_cryptosdk_edk_list_clean_up(struct aws_array_list *encrypted_data_keys) {
    assert(aws_cryptosdk_edk_list_is_valid(encrypted_data_keys));
    aws_array_list_clean_up(encrypted_data_keys);
}

void aws_cryptosdk_enc_materials_destroy_harness() {
    struct aws_cryptosdk_enc_materials *materials = can_fail_malloc(sizeof(*materials));
    if (materials) {
        materials->alloc = can_fail_allocator();
        __CPROVER_assume(aws_allocator_is_valid(materials->alloc));

        // Set up the signctx
        materials->signctx = can_fail_malloc(sizeof(*materials->signctx));
        if (materials->signctx) {
            ensure_sig_ctx_has_allocated_members(materials->signctx);
            __CPROVER_assume(aws_cryptosdk_sig_ctx_is_valid_cbmc(materials->signctx));
        }

        // Set up the unencrypted_data_key
        __CPROVER_assume(aws_byte_buf_is_bounded(&materials->unencrypted_data_key, MAX_NUM_ITEMS));
        ensure_byte_buf_has_allocated_buffer_member(&materials->unencrypted_data_key);

        // Set up the edk_list
        /* edk_list Precondition: We have a valid list */
        __CPROVER_assume(aws_cryptosdk_edk_list_is_bounded(&materials->encrypted_data_keys, MAX_NUM_ITEMS));
        ensure_cryptosdk_edk_list_has_allocated_list(&materials->encrypted_data_keys);
        __CPROVER_assume(aws_cryptosdk_edk_list_is_valid(&materials->encrypted_data_keys));

        // Stub until https://github.com/diffblue/cbmc/issues/5344 is fixed
        /* edk_list Precondition: The list has valid list elements */
        /*
        __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_bounded(&materials->encrypted_data_keys, MAX_STRING_LEN));
        ensure_cryptosdk_edk_list_has_allocated_list_elements(&materials->encrypted_data_keys);
        __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_valid(&materials->encrypted_data_keys));
        */
        // Set up the keyring trace
        __CPROVER_assume(aws_array_list_is_bounded(
            &materials->keyring_trace, MAX_NUM_ITEMS, sizeof(struct aws_cryptosdk_keyring_trace_record)));
        __CPROVER_assume(materials->keyring_trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
        ensure_array_list_has_allocated_data_member(&materials->keyring_trace);
        __CPROVER_assume(aws_array_list_is_valid(&materials->keyring_trace));
        ensure_trace_has_allocated_records(&materials->keyring_trace, MAX_STRING_LEN);
        __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&materials->keyring_trace));

        __CPROVER_assume(aws_cryptosdk_enc_materials_is_valid(materials));
    }

    // Run the function under test.
    // This frees all materials, and hence there are no post-conditions to check
    aws_cryptosdk_enc_materials_destroy(materials);
}
