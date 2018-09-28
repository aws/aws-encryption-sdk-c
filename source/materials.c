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
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/cipher.h>

struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg) {
    struct aws_cryptosdk_encryption_materials * enc_mat;
    enc_mat = aws_mem_acquire(alloc, sizeof(struct aws_cryptosdk_encryption_materials));

    if (!enc_mat) return NULL;
    enc_mat->alloc = alloc;
    enc_mat->alg = alg;
    memset(&enc_mat->unencrypted_data_key, 0, sizeof(struct aws_byte_buf));
    enc_mat->signctx = NULL;

    if (aws_cryptosdk_edk_list_init(alloc, &enc_mat->encrypted_data_keys)) {
        aws_mem_release(alloc, enc_mat);
        return NULL;
    }

    return enc_mat;
}

void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat) {
    if (enc_mat) {
        aws_cryptosdk_sig_abort(enc_mat->signctx);
        aws_byte_buf_clean_up_secure(&enc_mat->unencrypted_data_key);
        aws_cryptosdk_edk_list_clean_up(&enc_mat->encrypted_data_keys);
        aws_mem_release(enc_mat->alloc, enc_mat);
    }
}

// TODO: initialization for trailing signature key, if necessary
struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg) {
    struct aws_cryptosdk_decryption_materials * dec_mat;
    dec_mat = aws_mem_acquire(alloc, sizeof(struct aws_cryptosdk_decryption_materials));
    if (!dec_mat) return NULL;
    dec_mat->alloc = alloc;
    dec_mat->unencrypted_data_key.buffer = NULL;
    dec_mat->unencrypted_data_key.allocator = NULL;
    dec_mat->alg = alg;
    dec_mat->signctx = NULL;

    return dec_mat;
}

void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat) {
    if (dec_mat) {
        aws_cryptosdk_sig_abort(dec_mat->signctx);
        aws_byte_buf_secure_zero(&dec_mat->unencrypted_data_key);
        aws_byte_buf_clean_up(&dec_mat->unencrypted_data_key);
        aws_mem_release(dec_mat->alloc, dec_mat);
    }
}
