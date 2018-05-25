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
#include <stdlib.h> // abort

struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg,
                                                                                   size_t num_keys) {
    int ret;
    struct aws_cryptosdk_encryption_materials * enc_mat;
    enc_mat = alloc->mem_acquire(alloc, sizeof(struct aws_cryptosdk_encryption_materials));
    if (!enc_mat) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    enc_mat->alloc = alloc;
    enc_mat->alg = alg;

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
    ret = aws_byte_buf_init(alloc, &enc_mat->unencrypted_data_key, props->data_key_len);
    if (ret) {
        alloc->mem_release(alloc, enc_mat);
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    /*
     * Only pre-allocates the list of EDKs, which has length zero to start but can expand to num_keys before
     * needing reallocation. Byte buffers within EDKs will be allocated when individual EDKs are written.
     * If you do not use specific buffers within the EDK, be sure to set the allocators to NULL so that clean up
     * function will work properly.
     */
    ret = aws_array_list_init_dynamic(&enc_mat->encrypted_data_keys, alloc, num_keys, sizeof(struct aws_cryptosdk_edk));
    if (ret) {
        aws_byte_buf_clean_up(&enc_mat->unencrypted_data_key);
        alloc->mem_release(alloc, enc_mat);
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    return enc_mat;
}

void aws_cryptosdk_edk_clean_up(struct aws_cryptosdk_edk * edk) {
    aws_byte_buf_clean_up(&edk->provider_id);
    aws_byte_buf_clean_up(&edk->provider_info);
    aws_byte_buf_clean_up(&edk->enc_data_key);
}

void aws_cryptosdk_edk_list_clean_up(struct aws_array_list * edk_list) {
    size_t num_keys = edk_list->length;
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (aws_array_list_get_at_ptr(edk_list, (void **)&edk, key_idx)) abort();
        aws_cryptosdk_edk_clean_up(edk);
    }
    aws_array_list_clean_up(edk_list);
}

void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat) {
    if (enc_mat) {
        aws_cryptosdk_secure_zero_buf(&enc_mat->unencrypted_data_key);
        aws_byte_buf_clean_up(&enc_mat->unencrypted_data_key);
        aws_cryptosdk_edk_list_clean_up(&enc_mat->encrypted_data_keys);
        enc_mat->alloc->mem_release(enc_mat->alloc, enc_mat);
    }
}

// TODO: initialization for trailing signature key, if necessary
struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg) {
    int ret;
    struct aws_cryptosdk_decryption_materials * dec_mat;
    dec_mat = alloc->mem_acquire(alloc, sizeof(struct aws_cryptosdk_decryption_materials));
    if (!dec_mat) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    dec_mat->alloc = alloc;

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
    ret = aws_byte_buf_init(alloc, &dec_mat->unencrypted_data_key, props->data_key_len);
    if (ret) {
        alloc->mem_release(alloc, dec_mat);
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    return dec_mat;
}

void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat) {
    if (dec_mat) {
        aws_cryptosdk_secure_zero_buf(&dec_mat->unencrypted_data_key);
        aws_byte_buf_clean_up(&dec_mat->unencrypted_data_key);
        dec_mat->alloc->mem_release(dec_mat->alloc, dec_mat);
    }
}
