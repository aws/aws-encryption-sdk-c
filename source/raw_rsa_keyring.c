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
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/materials.h>
#include <aws/cryptosdk/private/raw_rsa_keyring.h>
#include <assert.h>

static int raw_rsa_keyring_encrypt_data_key(
    struct aws_cryptosdk_keyring *kr, struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;
    if (!self->rsa_public_key_pem) return AWS_CRYPTOSDK_ERR_BAD_STATE;
    struct aws_byte_buf *data_key = &enc_mat->unencrypted_data_key;
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(enc_mat->alg);
    size_t data_key_len = props->data_key_len;

    /* Failing this assert would mean that the length of the already generated data key was
     * different than the data key length prescribed by the algorithm suite
     */
    if (data_key_len != data_key->len) return AWS_OP_ERR;

    struct aws_cryptosdk_edk edk = { { 0 } };

    if (aws_cryptosdk_rsa_encrypt(
            &edk.enc_data_key, self->alloc, aws_byte_cursor_from_buf(data_key), self->rsa_public_key_pem,
            self->rsa_padding_mode)) {
        goto err;
    }

    if (aws_byte_buf_init(self->alloc, &edk.provider_id, self->provider_id->len)) goto err;
    edk.provider_id.len = edk.provider_id.capacity;

    if (aws_byte_buf_init(self->alloc, &edk.provider_info, self->master_key_id->len)) goto err;
    edk.provider_info.len = edk.provider_info.capacity;

    struct aws_byte_cursor provider_id = aws_byte_cursor_from_buf(&edk.provider_id);
    if (!aws_byte_cursor_write_from_whole_string(&provider_id, self->provider_id)) goto err;

    struct aws_byte_cursor provider_info = aws_byte_cursor_from_buf(&edk.provider_info);
    if (!aws_byte_cursor_write_from_whole_string(&provider_info, self->master_key_id)) goto err;

    if (aws_array_list_push_back(&enc_mat->encrypted_data_keys, &edk)) goto err;

    return AWS_OP_SUCCESS;

err:
    aws_cryptosdk_edk_clean_up(&edk);
    return AWS_OP_ERR;
}

static int raw_rsa_keyring_generate_data_key(
    struct aws_cryptosdk_keyring *kr, struct aws_cryptosdk_encryption_materials *enc_mat) {
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(enc_mat->alg);
    size_t data_key_len = props->data_key_len;

    if (aws_byte_buf_init(self->alloc, &enc_mat->unencrypted_data_key, data_key_len)) return AWS_OP_ERR;

    if (aws_cryptosdk_genrandom(enc_mat->unencrypted_data_key.buffer, data_key_len)) {
        aws_byte_buf_clean_up(&enc_mat->unencrypted_data_key);
        return AWS_OP_ERR;
    }
    enc_mat->unencrypted_data_key.len = enc_mat->unencrypted_data_key.capacity;
    return raw_rsa_keyring_encrypt_data_key(kr, enc_mat);
}

static int raw_rsa_keyring_decrypt_data_key(
    struct aws_cryptosdk_keyring *kr,
    struct aws_cryptosdk_decryption_materials *dec_mat,
    const struct aws_cryptosdk_decryption_request *request) {
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;
    if (!self->rsa_private_key_pem) return AWS_CRYPTOSDK_ERR_BAD_STATE;
    const struct aws_array_list *edks = &request->encrypted_data_keys;
    size_t num_edks = aws_array_list_length(edks);
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(dec_mat->alg);

    for (size_t edk_idx = 0; edk_idx < num_edks; ++edk_idx) {
        const struct aws_cryptosdk_edk *edk;

        if (aws_array_list_get_at_ptr(edks, (void **)&edk, edk_idx)) { return AWS_OP_ERR; }
        if (!edk->provider_id.len || !edk->provider_info.len || !edk->enc_data_key.len) continue;
        if (!aws_string_eq_byte_buf(self->provider_id, &edk->provider_id)) continue;
        if (!aws_string_eq_byte_buf(self->master_key_id, &edk->provider_info)) continue;
        const struct aws_byte_buf *edk_bytes = &edk->enc_data_key;
        if (aws_cryptosdk_rsa_decrypt(
                &dec_mat->unencrypted_data_key, request->alloc,
                aws_byte_cursor_from_array(edk_bytes->buffer, edk_bytes->len), self->rsa_private_key_pem,
                self->rsa_padding_mode)) {
            /* We are here either because of a ciphertext mismatch
             * or because of an OpenSSL error. In either case, nothing
             *  better to do than just moving on to next EDK, so clear the error code.
             */
            aws_reset_error();
        } else {
            assert(dec_mat->unencrypted_data_key.len == props->data_key_len);
            // Suppress unused variable warning with -DNDEBUG
            (void)props;
            return AWS_OP_SUCCESS;
        }
    }
    // None of the EDKs worked, clean up unencrypted data key buffer and return success per materials.h
    aws_byte_buf_clean_up(&dec_mat->unencrypted_data_key);

    return AWS_OP_SUCCESS;
}

static void raw_rsa_keyring_destroy(struct aws_cryptosdk_keyring *kr) {
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;
    aws_string_destroy((void *)self->master_key_id);
    aws_string_destroy((void *)self->provider_id);
    aws_string_destroy_secure((void *)self->rsa_private_key_pem);
    aws_string_destroy_secure((void *)self->rsa_public_key_pem);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_keyring_vt raw_rsa_keyring_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "raw RSA keyring",
    .destroy = raw_rsa_keyring_destroy,
    .generate_data_key = raw_rsa_keyring_generate_data_key,
    .encrypt_data_key = raw_rsa_keyring_encrypt_data_key,
    .decrypt_data_key = raw_rsa_keyring_decrypt_data_key
};

struct aws_cryptosdk_keyring *aws_cryptosdk_raw_rsa_keyring_new(
    struct aws_allocator *alloc,
    const uint8_t *master_key_id,
    size_t master_key_id_len,
    const uint8_t *provider_id,
    size_t provider_id_len,
    const char *rsa_private_key_pem,
    const char *rsa_public_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode) {
    struct raw_rsa_keyring *kr = aws_mem_acquire(alloc, sizeof(struct raw_rsa_keyring));
    if (!kr) return NULL;
    memset(kr, 0, sizeof(struct raw_rsa_keyring));

    kr->master_key_id = aws_string_new_from_array(alloc, master_key_id, master_key_id_len);
    if (!kr->master_key_id) goto err;

    kr->provider_id = aws_string_new_from_array(alloc, provider_id, provider_id_len);
    if (!kr->provider_id) goto err;

    kr->rsa_private_key_pem = aws_string_new_from_c_str(alloc, rsa_private_key_pem);

    kr->rsa_public_key_pem = aws_string_new_from_c_str(alloc, rsa_public_key_pem);
    if (!kr->rsa_public_key_pem && !kr->rsa_private_key_pem) goto err;

    kr->rsa_padding_mode = rsa_padding_mode;
    kr->alloc = alloc;

    aws_cryptosdk_keyring_base_init(&kr->base, &raw_rsa_keyring_vt);

    return (struct aws_cryptosdk_keyring *)kr;

err:
    aws_string_destroy((void *)kr->master_key_id);
    aws_string_destroy((void *)kr->provider_id);
    aws_mem_release(alloc, kr);
    return NULL;
}
