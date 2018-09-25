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

static int default_cmm_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                     struct aws_cryptosdk_encryption_materials ** output,
                                                     struct aws_cryptosdk_encryption_request * request) {
    struct aws_cryptosdk_encryption_materials * enc_mat = NULL;
    struct default_cmm * self = (struct default_cmm *) cmm;

    enc_mat = aws_cryptosdk_encryption_materials_new(request->alloc, request->requested_alg);
    if (!enc_mat) goto err;

    enc_mat->enc_context = request->enc_context;

    if (aws_cryptosdk_keyring_on_encrypt(self->kr,
                                         request->alloc,
                                         &enc_mat->unencrypted_data_key,
                                         &enc_mat->encrypted_data_keys,
                                         request->enc_context,
                                         request->requested_alg)) goto err;

// TODO: implement trailing signatures

    *output = enc_mat;
    return AWS_OP_SUCCESS;

err:
    *output = NULL;
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    return AWS_OP_ERR;
}

static int default_cmm_decrypt_materials(struct aws_cryptosdk_cmm * cmm,
                                         struct aws_cryptosdk_decryption_materials ** output,
                                         struct aws_cryptosdk_decryption_request * request) {
    struct aws_cryptosdk_decryption_materials * dec_mat;
    struct default_cmm * self = (struct default_cmm *) cmm;

    dec_mat = aws_cryptosdk_decryption_materials_new(request->alloc, request->alg);
    if (!dec_mat) goto err;

    if (aws_cryptosdk_keyring_on_decrypt(self->kr,
                                         request->alloc,
                                         &dec_mat->unencrypted_data_key,
                                         &request->encrypted_data_keys,
                                         request->enc_context,
                                         request->alg)) goto err;

    if (!dec_mat->unencrypted_data_key.buffer) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CANNOT_DECRYPT);
        goto err;
    }

// TODO: implement trailing signatures

    *output = dec_mat;
    return AWS_OP_SUCCESS;

err:
    *output = NULL;
    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    return AWS_OP_ERR;
}

static void default_cmm_destroy(struct aws_cryptosdk_cmm * cmm) {
    struct default_cmm * self = (struct default_cmm *) cmm;
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_cmm_vt default_cmm_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_cmm_vt),
    .name = "default cmm",
    .destroy = default_cmm_destroy,
    .generate_encryption_materials = default_cmm_generate_encryption_materials,
    .decrypt_materials = default_cmm_decrypt_materials
};

struct aws_cryptosdk_cmm * aws_cryptosdk_default_cmm_new(struct aws_allocator * alloc, struct aws_cryptosdk_keyring * kr) {
    struct default_cmm * cmm;
    cmm = aws_mem_acquire(alloc, sizeof(struct default_cmm));
    if (!cmm) return NULL;

    cmm->vt = &default_cmm_vt;
    cmm->alloc = alloc;
    cmm->kr = kr;

    return (struct aws_cryptosdk_cmm *) cmm;
}
