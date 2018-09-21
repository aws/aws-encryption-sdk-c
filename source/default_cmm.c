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
#include <aws/cryptosdk/default_cmm.h>

struct default_cmm {
    const struct aws_cryptosdk_cmm_vt * vt;
    struct aws_allocator * alloc;
    struct aws_cryptosdk_keyring * kr;
};

static int default_cmm_generate_encryption_materials(struct aws_cryptosdk_cmm *cmm,
                                                     struct aws_cryptosdk_encryption_materials **enc_mat,
                                                     struct aws_cryptosdk_encryption_request *request) {
    struct aws_cryptosdk_encryption_materials *my_enc_mat = NULL;
    struct default_cmm *self = (struct default_cmm *)cmm;

    my_enc_mat = aws_cryptosdk_encryption_materials_new(request->alloc, request->requested_alg);
    if (!my_enc_mat) goto err;

    my_enc_mat->enc_context = request->enc_context;

    struct aws_cryptosdk_keyring_on_encrypt_inputs inputs;
    inputs.enc_context = request->enc_context;
    inputs.alg = request->requested_alg;
    inputs.plaintext_size = request->plaintext_size;
    
    struct aws_cryptosdk_keyring_on_encrypt_outputs outputs;
    outputs.edks = &my_enc_mat->encrypted_data_keys;

    struct aws_byte_buf unencrypted_data_key = {0};

    if (aws_cryptosdk_keyring_on_encrypt(self->kr,
                                         &outputs,
                                         &unencrypted_data_key,
                                         &inputs)) goto err;
    // shallow copy, does NOT duplicate key bytes
    my_enc_mat->unencrypted_data_key = unencrypted_data_key;

// TODO: implement trailing signatures

    *enc_mat = my_enc_mat;
    return AWS_OP_SUCCESS;

err:
    *enc_mat = NULL;
    aws_cryptosdk_encryption_materials_destroy(my_enc_mat);
    return AWS_OP_ERR;
}

static int default_cmm_decrypt_materials(struct aws_cryptosdk_cmm *cmm,
                                         struct aws_cryptosdk_decryption_materials **dec_mat,
                                         struct aws_cryptosdk_decryption_request *request) {
    struct aws_cryptosdk_decryption_materials * my_dec_mat;
    struct default_cmm * self = (struct default_cmm *)cmm;

    my_dec_mat = aws_cryptosdk_decryption_materials_new(request->alloc, request->alg);
    if (!my_dec_mat) goto err;

    struct aws_cryptosdk_keyring_on_decrypt_inputs inputs;
    inputs.enc_context = request->enc_context;
    inputs.alg = request->alg;
    inputs.edks = &request->encrypted_data_keys;

    struct aws_cryptosdk_keyring_on_decrypt_outputs outputs = {{0}};

    if (aws_cryptosdk_keyring_on_decrypt(self->kr,
                                         &outputs,
                                         &inputs)) goto err;
    // shallow copy, does NOT duplicate key bytes
    my_dec_mat->unencrypted_data_key = outputs.unencrypted_data_key;

    if (!my_dec_mat->unencrypted_data_key.buffer) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CANNOT_DECRYPT);
        goto err;
    }

// TODO: implement trailing signatures

    *dec_mat = my_dec_mat;
    return AWS_OP_SUCCESS;

err:
    *dec_mat = NULL;
    aws_cryptosdk_decryption_materials_destroy(my_dec_mat);
    return AWS_OP_ERR;
}

static void default_cmm_destroy(struct aws_cryptosdk_cmm * cmm) {
    struct default_cmm * self = (struct default_cmm *)cmm;
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_cmm_vt default_cmm_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_cmm_vt),
    .name = "default cmm",
    .destroy = default_cmm_destroy,
    .generate_encryption_materials = default_cmm_generate_encryption_materials,
    .decrypt_materials = default_cmm_decrypt_materials
};

struct aws_cryptosdk_cmm *aws_cryptosdk_default_cmm_new(struct aws_allocator *alloc, struct aws_cryptosdk_keyring *kr) {
    struct default_cmm *cmm;
    cmm = aws_mem_acquire(alloc, sizeof(struct default_cmm));
    if (!cmm) return NULL;

    cmm->vt = &default_cmm_vt;
    cmm->alloc = alloc;
    cmm->kr = kr;

    return (struct aws_cryptosdk_cmm *)cmm;
}
