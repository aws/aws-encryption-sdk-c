/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/materials.h>

struct aws_cryptosdk_enc_materials *aws_cryptosdk_enc_materials_new(
    struct aws_allocator *alloc, enum aws_cryptosdk_alg_id alg) {
    struct aws_cryptosdk_enc_materials *enc_mat;
    enc_mat = aws_mem_acquire(alloc, sizeof(struct aws_cryptosdk_enc_materials));

    if (!enc_mat) return NULL;
    enc_mat->alloc = alloc;
    enc_mat->alg   = alg;
    memset(&enc_mat->unencrypted_data_key, 0, sizeof(struct aws_byte_buf));
    enc_mat->signctx = NULL;

    if (aws_cryptosdk_edk_list_init(alloc, &enc_mat->encrypted_data_keys)) {
        aws_mem_release(alloc, enc_mat);
        return NULL;
    }

    if (aws_cryptosdk_keyring_trace_init(alloc, &enc_mat->keyring_trace)) {
        aws_cryptosdk_edk_list_clean_up(&enc_mat->encrypted_data_keys);
        aws_mem_release(alloc, enc_mat);
        return NULL;
    }

    return enc_mat;
}

void aws_cryptosdk_enc_materials_destroy(struct aws_cryptosdk_enc_materials *enc_mat) {
    if (enc_mat) {
        aws_cryptosdk_sig_abort(enc_mat->signctx);
        aws_byte_buf_clean_up_secure(&enc_mat->unencrypted_data_key);
        aws_cryptosdk_edk_list_clean_up(&enc_mat->encrypted_data_keys);
        aws_cryptosdk_keyring_trace_clean_up(&enc_mat->keyring_trace);
        aws_mem_release(enc_mat->alloc, enc_mat);
    }
}

// TODO: initialization for trailing signature key, if necessary
struct aws_cryptosdk_dec_materials *aws_cryptosdk_dec_materials_new(
    struct aws_allocator *alloc, enum aws_cryptosdk_alg_id alg) {
    AWS_PRECONDITION(aws_allocator_is_valid(alloc));

    struct aws_cryptosdk_dec_materials *dec_mat = aws_mem_acquire(alloc, sizeof(struct aws_cryptosdk_dec_materials));
    if (!dec_mat) return NULL;
    dec_mat->alloc                          = alloc;
    dec_mat->unencrypted_data_key.buffer    = NULL;
    dec_mat->unencrypted_data_key.len       = 0;
    dec_mat->unencrypted_data_key.capacity  = 0;
    dec_mat->unencrypted_data_key.allocator = NULL;
    dec_mat->alg                            = alg;
    dec_mat->signctx                        = NULL;
    if (aws_cryptosdk_keyring_trace_init(alloc, &dec_mat->keyring_trace)) {
        aws_mem_release(alloc, dec_mat);
        return NULL;
    }

    return dec_mat;
}

void aws_cryptosdk_dec_materials_destroy(struct aws_cryptosdk_dec_materials *dec_mat) {
    if (dec_mat) {
        aws_cryptosdk_sig_abort(dec_mat->signctx);
        aws_byte_buf_clean_up_secure(&dec_mat->unencrypted_data_key);
        aws_cryptosdk_keyring_trace_clean_up(&dec_mat->keyring_trace);
        aws_mem_release(dec_mat->alloc, dec_mat);
    }
}

int aws_cryptosdk_keyring_on_encrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    /* Shallow copy of byte buffer: does NOT duplicate key bytes */
    const struct aws_byte_buf precall_data_key_buf = *unencrypted_data_key;

    /* Precondition: If a data key has not already been generated, there must be no EDKs.
     * Generating a new one and then pushing new EDKs on the list would cause the list of
     * EDKs to be inconsistent. (i.e., they would decrypt to different data keys.)
     */
    if (!precall_data_key_buf.buffer && aws_array_list_length(edks))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    AWS_CRYPTOSDK_PRIVATE_VF_CALL(
        on_encrypt, keyring, request_alloc, unencrypted_data_key, keyring_trace, edks, enc_ctx, alg);

    /* Postcondition: If this keyring generated data key, it must be the right length. */
    if (!precall_data_key_buf.buffer && unencrypted_data_key->buffer) {
        const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
        if (unencrypted_data_key->len != props->data_key_len) {
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
        }
    }

    /* Postcondition: If data key was generated before call, byte buffer must not have been
     * modified. Note that this only checks the metadata in the byte buffer and not the key
     * bytes themselves. Verifying the key bytes were unchanged would require making an extra
     * copy of the key bytes, a case of the cure being worse than the disease.
     */
    if (precall_data_key_buf.buffer) {
        if (memcmp(&precall_data_key_buf, unencrypted_data_key, sizeof(precall_data_key_buf)))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }
    return ret;
}

int aws_cryptosdk_keyring_on_decrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    const struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    /* Precondition: data key buffer must be unset. */
    if (unencrypted_data_key->buffer) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(
        on_decrypt, keyring, request_alloc, unencrypted_data_key, keyring_trace, edks, enc_ctx, alg);

    /* Postcondition: if data key was decrypted, its length must agree with algorithm
     * specification. If this is not the case, it either means ciphertext was tampered
     * with or the keyring implementation is not setting the length properly.
     */
    if (unencrypted_data_key->buffer) {
        const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
        if (unencrypted_data_key->len != props->data_key_len) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }
    return ret;
}
