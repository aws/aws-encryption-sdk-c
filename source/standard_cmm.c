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
#include <aws/cryptosdk/standard_cmm.h>

struct standard_cmm {
    const struct aws_cryptosdk_cmm_vt * vt;
    struct aws_allocator * alloc;
    struct aws_cryptosdk_mkp * mkp;
};

static int standard_cmm_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                      struct aws_cryptosdk_encryption_materials ** output,
                                                      struct aws_cryptosdk_encryption_request * request) {
    int ret;
    const int initial_master_key_list_size = 4; // will reallocate as necessary, this is just a guess

    struct aws_array_list master_keys;  // an array of pointers to master keys

    struct aws_cryptosdk_mk * master_key;
    struct aws_cryptosdk_encrypted_data_key encrypted_data_key;
    struct aws_cryptosdk_encryption_materials * enc_mat = NULL;

    size_t key_idx;
    size_t num_keys = 0;

    struct standard_cmm * self = (struct standard_cmm *) cmm;

    ret = aws_array_list_init_dynamic(&master_keys, self->alloc, initial_master_key_list_size, sizeof(struct aws_cryptosdk_mk *));
    if (ret) return aws_raise_error(ret);

    ret = aws_cryptosdk_mkp_append_master_keys(self->mkp, &master_keys, request->enc_context);
    if (ret) goto ERROR;
    num_keys = master_keys.length;

    enc_mat = aws_cryptosdk_encryption_materials_new(self->alloc, num_keys);
    if (!enc_mat) { ret = AWS_ERROR_OOM; goto ERROR; }

    enc_mat->enc_context = request->enc_context;
    enc_mat->alg = request->requested_alg;

    /* Produce unencrypted data key and first encrypted data key from the first master key. */
    ret = aws_array_list_get_at(&master_keys, (void *)&master_key, 0);
    if (ret) goto ERROR;

    ret = aws_cryptosdk_mk_generate_data_key(master_key,
                                             &enc_mat->unencrypted_data_key,
                                             &encrypted_data_key,
                                             enc_mat->enc_context,
                                             enc_mat->alg);
    if (ret) goto ERROR;

    ret = aws_array_list_push_back(&enc_mat->encrypted_data_keys, &encrypted_data_key);
    if (ret) goto ERROR;

    /* Re-encrypt unencrypted data key with each other master key. */
    for (key_idx = 1 ; key_idx < num_keys ; ++key_idx) {
        ret = aws_array_list_get_at(&master_keys, (void *)&master_key, key_idx);
        if (ret) goto ERROR;

        ret = aws_cryptosdk_mk_encrypt_data_key(master_key,
                                                &encrypted_data_key,
                                                &enc_mat->unencrypted_data_key,
                                                enc_mat->enc_context,
                                                enc_mat->alg);
        if (ret) goto ERROR;

        ret = aws_array_list_push_back(&enc_mat->encrypted_data_keys, &encrypted_data_key);
        if (ret) goto ERROR;
    }

/*
    generate_trailing_signature_key_pair(&enc_mat->trailing_signature_key_pair, enc_mat->alg);
    struct aws_byte_buf * serialized_public_key;
    ret = serialize_public_key(&serialized_public_key, &enc_mat->trailing_signature_key_pair.public_key);
    if (ret) goto ERROR;

    struct aws_hash_element * p_elem;
    int was_created;
    ret = aws_hash_table_create(enc_mat->enc_context, (void *)"aws-crypto-public-key", &p_elem, &was_created);
    if (ret) goto ERROR; // FIXME: handle resizing of hash table when necessary

    if (!was_created) {
        // this would mean we had previously generated a public key for this encryption context.
        // do we need to do anything special here?

        if (p_elem->value) {
            // do we need to do a test of whether there is an allocated byte buffer here already?
            // possibly refactor these two into single destroy function?
            aws_byte_buf_free(self->alloc, (struct aws_byte_buf *)p_elem->value);
            free(p_elem->value); // aws_byte_buf_free only frees pointer within byte buffer
        }
    }
    p_elem->value = (void *)serialized_public_key; // will need to free this later
*/

    *output = enc_mat;
    aws_array_list_clean_up(&master_keys);
    return AWS_OP_SUCCESS;

ERROR:
    aws_array_list_clean_up(&master_keys);
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    return aws_raise_error(ret);
}

static int standard_cmm_decrypt_materials(struct aws_cryptosdk_cmm * cmm,
                                          struct aws_cryptosdk_decryption_materials ** output,
                                          struct aws_cryptosdk_decryption_request * request) {
    int ret;
    struct aws_cryptosdk_decryption_materials * dec_mat;
    struct standard_cmm * self = (struct standard_cmm *) cmm;

    dec_mat = aws_cryptosdk_decryption_materials_new(self->alloc);
    if (!dec_mat) { ret = AWS_ERROR_OOM; goto ERROR; }

    ret = aws_cryptosdk_mkp_decrypt_data_key(self->mkp,
                                             &dec_mat->unencrypted_data_key,
                                             request->encrypted_data_keys,
                                             request->enc_context,
                                             request->alg);
    if (ret) goto ERROR;
/*
    struct aws_hash_element * p_elem;
    ret = aws_hash_table_find(request->enc_context, (void *)"aws-crypto-public-key", &p_elem);
    if (ret) goto ERROR;

    if (p_elem && p_elem->value) {
        ret = deserialize_public_key(&dec_mat->trailing_signature_key, (struct aws_byte_buf *)p_elem->value);
        if (ret) goto ERROR;
    }
*/
    *output = dec_mat;
    return AWS_OP_SUCCESS;

ERROR:
    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    return aws_raise_error(ret);
}

static void standard_cmm_destroy(struct aws_cryptosdk_cmm * cmm) {
    struct standard_cmm * self = (struct standard_cmm *) cmm;
    self->alloc->mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_cmm_vt standard_cmm_vt = {
    sizeof(struct aws_cryptosdk_cmm_vt),
    "standard cmm",
    standard_cmm_destroy,
    standard_cmm_generate_encryption_materials,
    standard_cmm_decrypt_materials
};

struct aws_cryptosdk_cmm * aws_cryptosdk_standard_cmm_new(struct aws_allocator * alloc, struct aws_cryptosdk_mkp * mkp) {
    struct standard_cmm * cmm;
    cmm = alloc->mem_acquire(alloc, sizeof(struct standard_cmm));
    if (!cmm) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    cmm->vt = &standard_cmm_vt;
    cmm->alloc = alloc;
    cmm->mkp = mkp;
    return (struct aws_cryptosdk_cmm *) cmm;
}
