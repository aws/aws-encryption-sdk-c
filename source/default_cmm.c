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
    struct aws_cryptosdk_mkp * mkp;
};

static int default_cmm_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                     struct aws_cryptosdk_encryption_materials ** output,
                                                     struct aws_cryptosdk_encryption_request * request) {
    const int initial_master_key_list_size = 4; // will reallocate as necessary, this is just a guess

    struct aws_array_list master_keys;  // an array of pointers to master keys

    struct aws_cryptosdk_mk * master_key;
    struct aws_cryptosdk_encryption_materials * enc_mat = NULL;

    size_t num_keys = 0;

    struct default_cmm * self = (struct default_cmm *) cmm;

    if (aws_array_list_init_dynamic(&master_keys, request->alloc, initial_master_key_list_size, sizeof(struct aws_cryptosdk_mk *))) {
        *output = NULL;
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_mkp_get_master_keys(self->mkp, &master_keys, request->enc_context)) goto err;

    num_keys = master_keys.length;
    if (!num_keys) { aws_raise_error(AWS_CRYPTOSDK_ERR_NO_MASTER_KEYS_FOUND); goto err; }

    enc_mat = aws_cryptosdk_encryption_materials_new(request->alloc, request->requested_alg, num_keys);
    if (!enc_mat) goto err;

    enc_mat->enc_context = request->enc_context;

    /* Produce unencrypted data key and first encrypted data key from the first master key. */
    if (aws_array_list_get_at(&master_keys, (void *)&master_key, 0)) goto err;

    if (aws_cryptosdk_mk_generate_data_key(master_key, enc_mat)) goto err;

    /* Re-encrypt unencrypted data key with each other master key. */
    for (size_t key_idx = 1 ; key_idx < num_keys ; ++key_idx) {
        if (aws_array_list_get_at(&master_keys, (void *)&master_key, key_idx)) goto err;

        if (aws_cryptosdk_mk_encrypt_data_key(master_key, enc_mat)) goto err;
    }

// TODO: implement trailing signatures

    *output = enc_mat;
    aws_array_list_clean_up(&master_keys);
    return AWS_OP_SUCCESS;

err:
    *output = NULL;
    aws_array_list_clean_up(&master_keys);
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

    if (aws_cryptosdk_mkp_decrypt_data_key(self->mkp, dec_mat, request)) goto err;

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

struct aws_cryptosdk_cmm * aws_cryptosdk_default_cmm_new(struct aws_allocator * alloc, struct aws_cryptosdk_mkp * mkp) {
    struct default_cmm * cmm;
    cmm = aws_mem_acquire(alloc, sizeof(struct default_cmm));
    if (!cmm) return NULL;

    cmm->vt = &default_cmm_vt;
    cmm->alloc = alloc;
    cmm->mkp = mkp;

    return (struct aws_cryptosdk_cmm *) cmm;
}
