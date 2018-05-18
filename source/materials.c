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
#include <aws/cryptosdk/cipher.h> // aws_cryptosdk_secure_zero

struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(struct aws_allocator * alloc, size_t num_keys) {
    int ret;
    struct aws_cryptosdk_encryption_materials * enc_mat;
    enc_mat = alloc->mem_acquire(alloc, sizeof(struct aws_cryptosdk_encryption_materials));
    if (!enc_mat) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    enc_mat->alloc = alloc;

    ret = aws_array_list_init_dynamic(&enc_mat->encrypted_data_keys, alloc, num_keys, sizeof(struct aws_cryptosdk_data_key));
    if (ret) {
        alloc->mem_release(alloc, enc_mat);
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    return enc_mat;
}

void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat) {
    if (enc_mat) {
        aws_cryptosdk_secure_zero(enc_mat->unencrypted_data_key.keybuf, MAX_DATA_KEY_SIZE);
        aws_array_list_clean_up(&enc_mat->encrypted_data_keys);
        enc_mat->alloc->mem_release(enc_mat->alloc, enc_mat);
    }
}

// TODO: initialization for trailing signature key, if necessary
struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(struct aws_allocator * alloc) {
    int ret;
    struct aws_cryptosdk_decryption_materials * dec_mat;
    dec_mat = alloc->mem_acquire(alloc, sizeof(struct aws_cryptosdk_decryption_materials));
    if (!dec_mat) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    dec_mat->alloc = alloc;
    return dec_mat;
}

void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat) {
    if (dec_mat) {
        aws_cryptosdk_secure_zero(dec_mat->unencrypted_data_key.keybuf, MAX_DATA_KEY_SIZE);
        dec_mat->alloc->mem_release(dec_mat->alloc, dec_mat);
    }
}
