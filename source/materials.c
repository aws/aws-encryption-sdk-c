#include <aws/cryptosdk/materials.h>

int aws_cryptosdk_default_generate_encryption_materials(struct aws_cryptosdk_materials_manager * self,
                                                        struct aws_cryptosdk_encryption_materials ** encryption_materials,
                                                        struct aws_common_hash_table * enc_context,
                                                        size_t plaintext_size) {
    int ret;

    size_t num_keys = self->master_keys.current_size;
    size_t key_idx;

    struct aws_cryptosdk_master_key * master_key;

    ret = aws_array_list_get_at_ptr(&self->master_keys, (void **)&master_key, 0);
    if (ret) {
        return aws_raise_error(ret);
    }

    struct aws_cryptosdk_encryption_materials * enc_mat;
    enc_mat = aws_cryptosdk_alloc_encryption_materials(self->alloc, num_keys);
    if (!enc_mat) {
        return aws_raise_error(AWS_ERROR_OOM);
    }
    enc_mat->enc_context = enc_context;
    enc_mat->alg_id = self->alg_id;

    /* Produce unencrypted data key and first encrypted data key from the first master key. */
    struct aws_cryptosdk_encrypted_data_key * encrypted_data_key;
    ret = aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&encrypted_data_key, 0);
    if (ret) {
        aws_cryptosdk_free_encryption_materials(enc_mat);
        return aws_raise_error(ret);
    }

    ret = master_key->generate_data_key(master_key, &enc_mat->unencrypted_data_key, encrypted_data_key, enc_context, self->alg_id);
    if (ret) {
        aws_cryptosdk_free_encryption_materials(enc_mat);
        return aws_raise_error(ret);
    }

    /* Re-encrypt unencrypted data key with each other master key. */
    for (key_idx = 1 ; key_idx < num_keys ; ++key_idx) {
        ret = aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&encrypted_data_key, key_idx);
        if (ret) {
            aws_cryptosdk_free_encryption_materials(enc_mat);
            return aws_raise_error(ret);
        }

        ret = master_key->encrypt_data_key(master_key, &enc_mat->unencrypted_data_key, encrypted_data_key, enc_context, self->alg_id);
        if (ret) {
            aws_cryptosdk_free_encryption_materials(enc_mat);
            return aws_raise_error(ret);
        }
    }
    // FIXME: how do we get enc_mat->trailing_signature_key?

    *encryption_materials = enc_mat;
    return AWS_OP_SUCCESS;
}

struct aws_cryptosdk_encryption_materials * aws_cryptosdk_alloc_encryption_materials(struct aws_allocator * alloc, size_t num_keys) {
    int ret;
    struct aws_cryptosdk_encryption_materials * enc_mat;
    enc_mat = alloc->mem_acquire(alloc, sizeof(struct aws_cryptosdk_encryption_materials));
    if (!enc_mat) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    enc_mat->alloc = alloc;

    ret = aws_array_list_init_dynamic(&enc_mat->encrypted_data_keys, alloc, num_keys, sizeof(struct aws_cryptosdk_encrypted_data_key));
    if (ret) {
        alloc->mem_release(alloc, enc_mat);
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    return enc_mat;
}

void aws_cryptosdk_free_encryption_materials(struct aws_cryptosdk_encryption_materials * enc_mat) {
    if (enc_mat) {
        aws_array_list_clean_up(&enc_mat->encrypted_data_keys);
        enc_mat->alloc->mem_release(enc_mat->alloc, enc_mat);
    }
}
