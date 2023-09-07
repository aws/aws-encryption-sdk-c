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

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>

#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/keyring_trace.h>

#include <make_common_data_structures.h>

#include <proof_helpers/make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/utils.h>

/**
 * Stub for the virtual function on_decrypt of a aws_cryptosdk_keyring_vt structure.
 * Must implement if used for decryption.
 * It should be as nondeterministic as possible to increase coverage on the operation under
 * verfication; thus, it also triggers states with errors.
 *
 * Implementations must properly initialize the unencrypted data key buffer when an
 * EDK is decrypted and leave the unencrypted data key buffer pointer set to NULL
 * when no EDK is decrypted. Implementations should return AWS_OP_SUCCESS regardless
 * of whether the unencrypted data key is recovered, except in cases of internal errors.
 */
int on_decrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    /* Check validity for all inputs to avoid memory-safety violations. */
    assert(aws_cryptosdk_keyring_is_valid(keyring));
    assert(aws_allocator_is_valid(request_alloc));
    assert(aws_byte_buf_is_valid(unencrypted_data_key));
    assert(aws_cryptosdk_keyring_trace_is_valid(keyring_trace));
    assert(aws_cryptosdk_edk_list_is_valid(edks));
    assert(aws_cryptosdk_edk_list_elements_are_valid(edks));
    assert((enc_ctx == NULL) || aws_hash_table_is_valid(enc_ctx));

    if (unencrypted_data_key->buffer == NULL) {
        const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
        if (props != NULL) {
            __CPROVER_assume(aws_byte_buf_is_bounded(unencrypted_data_key, props->data_key_len));
            ensure_byte_buf_has_allocated_buffer_member(unencrypted_data_key);
            /*
             * This satisfies the post-condition that if data key was decrypted,
             * its length must agree with algorithm specification.
             * The nondeterminism increases coverage.
             */
            if (nondet_bool()) unencrypted_data_key->len = props->data_key_len;
            unencrypted_data_key->allocator = request_alloc;
            __CPROVER_assume(aws_byte_buf_is_valid(unencrypted_data_key));
        }
    }
    int ret;
    return ret;
}

void aws_cryptosdk_keyring_on_decrypt_harness() {
    /* Non-deterministic inputs. */
    const struct aws_cryptosdk_keyring_vt vtable = { .vt_size    = sizeof(struct aws_cryptosdk_keyring_vt),
                                                     .name       = ensure_c_str_is_allocated(SIZE_MAX),
                                                     .destroy    = nondet_voidp(),
                                                     .on_encrypt = nondet_voidp(),
                                                     .on_decrypt = nondet_bool() ? NULL : on_decrypt };
    struct aws_cryptosdk_keyring keyring;
    ensure_cryptosdk_keyring_has_allocated_members(&keyring, &vtable);
    __CPROVER_assume(aws_cryptosdk_keyring_is_valid(&keyring));
    __CPROVER_assume(keyring.vtable != NULL);

    struct aws_allocator *request_alloc = can_fail_allocator();
    __CPROVER_assume(aws_allocator_is_valid(request_alloc));

    struct aws_array_list keyring_trace;
    __CPROVER_assume(
        aws_array_list_is_bounded(&keyring_trace, MAX_ITEM_SIZE, sizeof(struct aws_cryptosdk_keyring_trace_record)));
    __CPROVER_assume(keyring_trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&keyring_trace);
    __CPROVER_assume(aws_array_list_is_valid(&keyring_trace));
    ensure_trace_has_allocated_records(&keyring_trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&keyring_trace));

    struct aws_byte_buf unencrypted_data_key;
    if (nondet_bool()) {
        /* The caller could send an empty unencrypted_data_key. */
        unencrypted_data_key.buffer = NULL;
    } else {
        ensure_byte_buf_has_allocated_buffer_member(&unencrypted_data_key);
    }
    __CPROVER_assume(aws_byte_buf_is_valid(&unencrypted_data_key));

    struct aws_array_list edks;
    __CPROVER_assume(aws_cryptosdk_edk_list_is_bounded(&edks, NUM_ELEMS));
    ensure_cryptosdk_edk_list_has_allocated_list(&edks);
    __CPROVER_assume(aws_cryptosdk_edk_list_is_valid(&edks));
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_bounded(&edks, SIZE_MAX));
    ensure_cryptosdk_edk_list_has_allocated_list_elements(&edks);
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_valid(&edks));

    struct aws_hash_table *enc_ctx = malloc(sizeof(*enc_ctx));
    if (enc_ctx != NULL) {
        ensure_allocated_hash_table(enc_ctx, MAX_TABLE_SIZE);
        __CPROVER_assume(aws_hash_table_is_valid(enc_ctx));
        ensure_hash_table_has_valid_destroy_functions(enc_ctx);
        size_t empty_slot_idx;
        __CPROVER_assume(aws_hash_table_has_an_empty_slot(enc_ctx, &empty_slot_idx));
    }

    enum aws_cryptosdk_alg_id alg;

    /* Operation under verification. */
    if (aws_cryptosdk_keyring_on_decrypt(
            &keyring, request_alloc, &unencrypted_data_key, &keyring_trace, &edks, enc_ctx, alg) == AWS_OP_SUCCESS) {
        assert(aws_byte_buf_is_valid(&unencrypted_data_key));
    }

    /* Post-conditions. */
    assert(aws_cryptosdk_keyring_is_valid(&keyring));
    assert(aws_allocator_is_valid(request_alloc));
    assert(aws_cryptosdk_keyring_trace_is_valid(&keyring_trace));
    assert(aws_cryptosdk_edk_list_is_valid(&edks));
    assert(aws_cryptosdk_edk_list_elements_are_valid(&edks));
    if (enc_ctx != NULL) assert(aws_hash_table_is_valid(enc_ctx));
}
