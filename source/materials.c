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

int aws_cryptosdk_edk_list_init(struct aws_allocator *alloc, struct aws_array_list *edk_list) {
    const int initial_size = 4; // just a guess, this will resize as necessary
    return aws_array_list_init_dynamic(edk_list,
                                       alloc,
                                       initial_size,
                                       sizeof(struct aws_cryptosdk_edk));
}

struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(struct aws_allocator * alloc,
                                                                                   enum aws_cryptosdk_alg_id alg) {
    struct aws_cryptosdk_encryption_materials * enc_mat;
    enc_mat = aws_mem_acquire(alloc, sizeof(struct aws_cryptosdk_encryption_materials));
    if (!enc_mat) return NULL;

    if (aws_cryptosdk_edk_list_init(alloc, &enc_mat->encrypted_data_keys)) {
        aws_mem_release(alloc, enc_mat);
        return NULL;
    }

    enc_mat->alloc = alloc;
    enc_mat->alg = alg;

    /* Not the same as aws_byte_buf_secure_zero, which zeros the data bytes of an
     * allocated buffer. This sets the initial state for an unallocated buffer.
     */
    aws_secure_zero(&enc_mat->unencrypted_data_key, sizeof(struct aws_byte_buf));

    return enc_mat;
}

void aws_cryptosdk_edk_clean_up(struct aws_cryptosdk_edk * edk) {
    aws_byte_buf_clean_up(&edk->provider_id);
    aws_byte_buf_clean_up(&edk->provider_info);
    aws_byte_buf_clean_up(&edk->enc_data_key);
}

void aws_cryptosdk_edk_list_clear(struct aws_array_list * edk_list) {
    size_t num_keys = edk_list->length;
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (!aws_array_list_get_at_ptr(edk_list, (void **)&edk, key_idx)) {
            aws_cryptosdk_edk_clean_up(edk);
        }
    }
    aws_array_list_clear(edk_list);
}

void aws_cryptosdk_edk_list_clean_up(struct aws_array_list * edk_list) {
    aws_cryptosdk_edk_list_clear(edk_list);
    aws_array_list_clean_up(edk_list);
}

void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat) {
    if (enc_mat) {
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
    dec_mat->alg = alg;

    /* Not the same as aws_byte_buf_secure_zero, which zeros the data bytes of an
     * allocated buffer. This sets the initial state for an unallocated buffer.
     */
    aws_secure_zero(&dec_mat->unencrypted_data_key, sizeof(struct aws_byte_buf));

    return dec_mat;
}

void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat) {
    if (dec_mat) {
        aws_byte_buf_clean_up_secure(&dec_mat->unencrypted_data_key);
        aws_mem_release(dec_mat->alloc, dec_mat);
    }
}
