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
    struct aws_cryptosdk_edk encrypted_data_key;
    struct aws_cryptosdk_encryption_materials * enc_mat = NULL;

    size_t num_keys = 0;

    struct default_cmm * self = (struct default_cmm *) cmm;

    if (aws_array_list_init_dynamic(&master_keys, self->alloc, initial_master_key_list_size, sizeof(struct aws_cryptosdk_mk *))) {
        *output = NULL;
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_mkp_get_master_keys(self->mkp, &master_keys, request->enc_context)) goto ERROR;

    num_keys = master_keys.length;
    if (!num_keys) { aws_raise_error(AWS_CRYPTOSDK_ERR_NO_MASTER_KEYS_FOUND); goto ERROR; }

    enc_mat = aws_cryptosdk_encryption_materials_new(self->alloc, request->requested_alg, num_keys);
    if (!enc_mat) goto ERROR;

    enc_mat->enc_context = request->enc_context;

    /* Produce unencrypted data key and first encrypted data key from the first master key. */
    if (aws_array_list_get_at(&master_keys, (void *)&master_key, 0)) goto ERROR;

    if (aws_cryptosdk_mk_generate_data_key(master_key,
                                           &enc_mat->unencrypted_data_key,
                                           &encrypted_data_key,
                                           enc_mat->enc_context,
                                           enc_mat->alg)) goto ERROR;

    if (aws_array_list_push_back(&enc_mat->encrypted_data_keys, &encrypted_data_key)) goto ERROR;

    /* Re-encrypt unencrypted data key with each other master key. */
    for (size_t key_idx = 1 ; key_idx < num_keys ; ++key_idx) {
        if (aws_array_list_get_at(&master_keys, (void *)&master_key, key_idx)) goto ERROR;

        if (aws_cryptosdk_mk_encrypt_data_key(master_key,
                                              &encrypted_data_key,
                                              &enc_mat->unencrypted_data_key,
                                              enc_mat->enc_context,
                                              enc_mat->alg)) goto ERROR;

        if (aws_array_list_push_back(&enc_mat->encrypted_data_keys, &encrypted_data_key)) goto ERROR;
    }

// TODO: implement trailing signatures
#if 0
    generate_trailing_signature_key_pair(&enc_mat->trailing_signature_key_pair, enc_mat->alg);
    struct aws_byte_buf * serialized_public_key;
    if (serialize_public_key(&serialized_public_key, &enc_mat->trailing_signature_key_pair.public_key)) goto ERROR;

    struct aws_hash_element * p_elem;
    int was_created;
    if (aws_hash_table_create(enc_mat->enc_context, (void *)"aws-crypto-public-key", &p_elem, &was_created)) {
        goto ERROR; // FIXME: handle resizing of hash table when necessary
    }

    if (!was_created) {
        // this would mean we had previously generated a public key for this encryption context.
        // do we need to do anything special here?

        if (p_elem->value) {
            // do we need to do a test of whether there is an allocated byte buffer here already?
            // possibly refactor these two into single destroy function?
            aws_byte_buf_clean_up((struct aws_byte_buf *)p_elem->value);
            // FIXME: definitely shouldn't be using free
            free(p_elem->value); // aws_byte_buf_clean_up only frees pointer within byte buffer
        }
    }
    p_elem->value = (void *)serialized_public_key; // will need to free this later
#endif // #if 0

    *output = enc_mat;
    aws_array_list_clean_up(&master_keys);
    return AWS_OP_SUCCESS;

ERROR:
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

    dec_mat = aws_cryptosdk_decryption_materials_new(self->alloc, request->alg);
    if (!dec_mat) goto ERROR;

    if (aws_cryptosdk_mkp_decrypt_data_key(self->mkp,
                                           &dec_mat->unencrypted_data_key,
                                           &request->encrypted_data_keys,
                                           request->enc_context,
                                           request->alg)) goto ERROR;

// TODO: implement trailing signatures
#if 0
    struct aws_hash_element * p_elem;
    if (aws_hash_table_find(request->enc_context, (void *)"aws-crypto-public-key", &p_elem)) goto ERROR;

    if (p_elem && p_elem->value) {
        if (deserialize_public_key(&dec_mat->trailing_signature_key, (struct aws_byte_buf *)p_elem->value)) goto ERROR;
    }
#endif // #if 0

    *output = dec_mat;
    return AWS_OP_SUCCESS;

ERROR:
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
    if (!cmm) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    cmm->vt = &default_cmm_vt;
    cmm->alloc = alloc;
    cmm->mkp = mkp;
    return (struct aws_cryptosdk_cmm *) cmm;
}
