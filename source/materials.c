#include <aws/cryptosdk/materials.h>

struct aws_cryptosdk_cmm_default {
    struct aws_allocator * alloc;
    enum aws_cryptosdk_cmm_type type;
    enum aws_cryptosdk_alg_id alg_id;
    struct aws_array_list master_keys;
};

int aws_cryptosdk_cmm_default_generate_encryption_materials(struct aws_cryptosdk_cmm * cmm,
                                                            struct aws_cryptosdk_encryption_materials ** output,
                                                            struct aws_common_hash_table * enc_context) {
    int ret;
    struct aws_cryptosdk_cmm_default * self = (struct aws_cryptosdk_cmm_default *) cmm;

    size_t num_keys = self->master_keys.current_size;
    size_t key_idx;

    struct aws_cryptosdk_encryption_materials * enc_mat;

    enc_mat = aws_cryptosdk_encryption_materials_new(self->alloc, num_keys);
    if (!enc_mat) { ret = AWS_ERROR_OOM; goto ERROR; }

    enc_mat->enc_context = enc_context;
    enc_mat->alg_id = self->alg_id;

    /* Produce unencrypted data key and first encrypted data key from the first master key. */
    struct aws_cryptosdk_mk * master_key;
    ret = aws_array_list_get_at_ptr(&self->master_keys, (void **)&master_key, 0);
    if (ret) goto ERROR;

    struct aws_cryptosdk_encrypted_data_key * encrypted_data_key;
    ret = aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&encrypted_data_key, 0);
    if (ret) goto ERROR;

    ret = aws_cryptosdk_mk_vt_list[master_key->type].generate_data_key(master_key,
                                                                       &enc_mat->unencrypted_data_key,
                                                                       encrypted_data_key);
    if (ret) goto ERROR;

    /* Re-encrypt unencrypted data key with each other master key. */
    for (key_idx = 1 ; key_idx < num_keys ; ++key_idx) {
        ret = aws_array_list_get_at_ptr(&self->master_keys, (void **)&master_key, key_idx);
        if (ret) goto ERROR;

        ret = aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&encrypted_data_key, key_idx);
        if (ret) goto ERROR;

        ret = aws_cryptosdk_mk_vt_list[master_key->type].encrypt_data_key(master_key,
                                                                          encrypted_data_key,
                                                                          &enc_mat->unencrypted_data_key);
        if (ret) goto ERROR;
    }

    struct aws_common_hash_element * p_elem;
    int was_created;
    generate_trailing_signature_key_pair(&enc_mat->trailing_signature_key_pair, self->alg_id);
    ret = aws_common_hash_table_create(enc_mat->enc_context, (void *)"aws-crypto-public-key", &p_elem, &was_created);
    if (was_created) {
        // do we need to copy this? does it need to be encoded a particular way?
        p_elem->value = (void *)&enc_mat->trailing_signature_key_pair.public_key;
    } else {
        // this would mean we had previously generated a public key for this encryption context, what happens here?
        p_elem->value = (void *)&enc_mat->trailing_signature_key_pair.public_key;
    }

    *output = enc_mat;
    return AWS_OP_SUCCESS;

ERROR:
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    return aws_raise_error(ret);
}

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
