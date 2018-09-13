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
#include <aws/cryptosdk/private/raw_aes_keyring.h>
#include <aws/cryptosdk/private/enc_context.h>
#include <aws/cryptosdk/private/utils.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/materials.h>
#include <assert.h>

static int serialize_aad(struct aws_byte_buf *aad, struct aws_allocator *alloc, const struct aws_hash_table *enc_context) {
    size_t aad_len;

    memset(aad, 0, sizeof(*aad));

    if (aws_cryptosdk_context_size(&aad_len, enc_context)
        || aws_byte_buf_init(alloc, aad, aad_len)
        || aws_cryptosdk_context_serialize(alloc, aad, enc_context)) {
        aws_byte_buf_clean_up(aad);

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_serialize_provider_info_init(struct aws_allocator * alloc,
                                               struct aws_byte_buf * output,
                                               const struct aws_string * master_key_id,
                                               const uint8_t * iv) {
    size_t serialized_len = master_key_id->len + RAW_AES_KR_IV_LEN + 8; // 4 for tag len, 4 for iv len
    if (aws_byte_buf_init(alloc, output, serialized_len)) {
        return AWS_OP_ERR;
    }
    output->len = output->capacity;
    struct aws_byte_cursor cur = aws_byte_cursor_from_buf(output);
    if (!aws_byte_cursor_write_from_whole_string(&cur, master_key_id)) goto write_err;
    if (!aws_byte_cursor_write_be32(&cur, RAW_AES_KR_TAG_LEN * 8)) goto write_err;
    if (!aws_byte_cursor_write_be32(&cur, RAW_AES_KR_IV_LEN)) goto write_err;
    if (!aws_byte_cursor_write(&cur, iv, RAW_AES_KR_IV_LEN)) goto write_err;

    return AWS_OP_SUCCESS;

write_err:
    // We should never get here, because buffer was allocated locally to be long enough.
    aws_byte_buf_clean_up(output);
    return aws_raise_error(AWS_ERROR_UNKNOWN);
}

bool aws_cryptosdk_parse_provider_info(struct aws_cryptosdk_keyring * kr,
                                       struct aws_byte_buf * iv,
                                       const struct aws_byte_buf * provider_info) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;
    size_t mkid_len = self->master_key_id->len;
    size_t serialized_len = mkid_len + RAW_AES_KR_IV_LEN + 8;
    if (serialized_len != provider_info->len) return false;

    struct aws_byte_cursor cur = aws_byte_cursor_from_buf(provider_info);

    struct aws_byte_cursor mkid = aws_byte_cursor_advance_nospec(&cur, mkid_len);
    if (!mkid.ptr) goto READ_ERR;
    if (!aws_string_eq_byte_cursor(self->master_key_id, &mkid)) return false;

    uint32_t tag_len, iv_len;
    if (!aws_byte_cursor_read_be32(&cur, &tag_len)) goto READ_ERR;
    if (tag_len != RAW_AES_KR_TAG_LEN * 8) return false;

    if (!aws_byte_cursor_read_be32(&cur, &iv_len)) goto READ_ERR;
    if (iv_len != RAW_AES_KR_IV_LEN) return false;

    *iv = aws_byte_buf_from_array(cur.ptr, cur.len);
    return true;

READ_ERR:
    // We should never get here because we verified cursor was exactly the right length
    aws_raise_error(AWS_ERROR_UNKNOWN);
    return false;
}

int aws_cryptosdk_raw_aes_keyring_encrypt_data_key_with_iv(struct aws_cryptosdk_keyring * kr,
                                                      struct aws_cryptosdk_encryption_materials * enc_mat,
                                                      const uint8_t * iv) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;

    struct aws_byte_buf * data_key = &enc_mat->unencrypted_data_key;

    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(enc_mat->alg);
    size_t data_key_len = props->data_key_len;

    /* Failing this assert would mean that the length of the already generated data key was
     * different than the data key length prescribed by the algorithm suite
     */
    assert(data_key_len == data_key->len);

    struct aws_byte_buf aad;

    if (serialize_aad(&aad, enc_mat->alloc, enc_mat->enc_context)) {
        return AWS_OP_ERR;
    }

    struct aws_cryptosdk_edk edk = {{0}};
    /* Encrypted data key bytes same length as unencrypted data key in GCM.
     * enc_data_key field also includes tag afterward.
     */
    if (aws_byte_buf_init(self->alloc, &edk.enc_data_key, data_key_len + RAW_AES_KR_TAG_LEN)) {
        aws_byte_buf_clean_up(&aad);
        return AWS_OP_ERR;
    }
    struct aws_byte_buf edk_bytes = aws_byte_buf_from_array(edk.enc_data_key.buffer, data_key_len);
    struct aws_byte_buf tag = aws_byte_buf_from_array(edk.enc_data_key.buffer + data_key_len, RAW_AES_KR_TAG_LEN);
    if (aws_cryptosdk_aes_gcm_encrypt(&edk_bytes,
                                      &tag,
                                      aws_byte_cursor_from_buf(data_key),
                                      aws_byte_cursor_from_array(iv, RAW_AES_KR_IV_LEN),
                                      aws_byte_cursor_from_buf(&aad),
                                      self->raw_key)) goto err;
    edk.enc_data_key.len = edk.enc_data_key.capacity;

    if (aws_cryptosdk_serialize_provider_info_init(self->alloc, &edk.provider_info, self->master_key_id, iv))
        goto err;

    if (aws_byte_buf_init(self->alloc, &edk.provider_id, self->provider_id->len)) goto err;
    edk.provider_id.len = edk.provider_id.capacity;
    struct aws_byte_cursor provider_id = aws_byte_cursor_from_buf(&edk.provider_id);
    if (!aws_byte_cursor_write_from_whole_string(&provider_id, self->provider_id)) goto err;

    if (aws_array_list_push_back(&enc_mat->encrypted_data_keys, &edk)) goto err;

    aws_byte_buf_clean_up(&aad);
    return AWS_OP_SUCCESS;

err:
    aws_cryptosdk_edk_clean_up(&edk);
    aws_byte_buf_clean_up(&aad);
    return AWS_OP_ERR;
}

static int raw_aes_keyring_encrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                       struct aws_cryptosdk_encryption_materials * enc_mat) {
    uint8_t iv[RAW_AES_KR_IV_LEN];
    if (aws_cryptosdk_genrandom(iv, RAW_AES_KR_IV_LEN)) return AWS_OP_ERR;

    return aws_cryptosdk_raw_aes_keyring_encrypt_data_key_with_iv(kr, enc_mat, iv);
}

static int raw_aes_keyring_generate_data_key(struct aws_cryptosdk_keyring * kr,
                                        struct aws_cryptosdk_encryption_materials * enc_mat) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;

    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(enc_mat->alg);
    size_t data_key_len = props->data_key_len;

    if (aws_byte_buf_init(self->alloc, &enc_mat->unencrypted_data_key, data_key_len)) return AWS_OP_ERR;

    if (aws_cryptosdk_genrandom(enc_mat->unencrypted_data_key.buffer, data_key_len)) {
        aws_byte_buf_clean_up(&enc_mat->unencrypted_data_key);
        return AWS_OP_ERR;
    }
    enc_mat->unencrypted_data_key.len = enc_mat->unencrypted_data_key.capacity;

    return raw_aes_keyring_encrypt_data_key(kr, enc_mat);
}


static int raw_aes_keyring_decrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                       struct aws_cryptosdk_decryption_materials * dec_mat,
                                       const struct aws_cryptosdk_decryption_request * request) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;

    struct aws_byte_buf aad;

    if (serialize_aad(&aad, request->alloc, request->enc_context)) {
        return AWS_OP_ERR;
    }

    const struct aws_array_list * edks = &request->encrypted_data_keys;
    size_t num_edks = aws_array_list_length(edks);

    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(dec_mat->alg);
    size_t edk_len = props->data_key_len;

    if (aws_byte_buf_init(request->alloc, &dec_mat->unencrypted_data_key, props->data_key_len)) {
        aws_byte_buf_clean_up(&aad);
        return AWS_OP_ERR;
    }

    for (size_t edk_idx = 0; edk_idx < num_edks; ++edk_idx) {
        const struct aws_cryptosdk_edk * edk;
        if (aws_array_list_get_at_ptr(edks, (void **)&edk, edk_idx)) {
            aws_byte_buf_clean_up(&aad);
            return AWS_OP_ERR;
        }
        if (!edk->provider_id.len || !edk->provider_info.len || !edk->enc_data_key.len) continue;

        if (!aws_string_eq_byte_buf(self->provider_id, &edk->provider_id)) continue;

        struct aws_byte_buf iv;
        if (!aws_cryptosdk_parse_provider_info(kr, &iv, &edk->provider_info)) continue;

        const struct aws_byte_buf * edk_bytes = &edk->enc_data_key;

        /* Using GCM, so encrypted and unencrypted data key have same length, i.e. edk_len.
         * edk_bytes->buffer holds encrypted data key followed by GCM tag.
         */
        if (edk_len + RAW_AES_KR_TAG_LEN != edk_bytes->len) continue;

        if (aws_cryptosdk_aes_gcm_decrypt(&dec_mat->unencrypted_data_key,
                                          aws_byte_cursor_from_array(edk_bytes->buffer, edk_len),
                                          aws_byte_cursor_from_array(edk_bytes->buffer + edk_len,
                                                                     RAW_AES_KR_TAG_LEN),
                                          aws_byte_cursor_from_buf(&iv),
                                          aws_byte_cursor_from_buf(&aad),
                                          self->raw_key)) {
            /* We are here either because of a ciphertext/tag mismatch (e.g., wrong encryption
             * context) or because of an OpenSSL error. In either case, nothing better to do
             * than just moving on to next EDK, so clear the error code.
             */
            aws_reset_error();
        } else {
            assert(dec_mat->unencrypted_data_key.len == edk_len);
            goto success;
        }
    }
    // None of the EDKs worked, clean up unencrypted data key buffer and return success per materials.h
    aws_byte_buf_clean_up(&dec_mat->unencrypted_data_key);

success:
    aws_byte_buf_clean_up(&aad);
    return AWS_OP_SUCCESS;
}

static void raw_aes_keyring_destroy(struct aws_cryptosdk_keyring * kr) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;
    aws_string_destroy((void *)self->master_key_id);
    aws_string_destroy((void *)self->provider_id);
    aws_string_destroy_secure((void *)self->raw_key);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_keyring_vt raw_aes_keyring_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "raw AES keyring",
    .destroy = raw_aes_keyring_destroy,
    .generate_data_key = raw_aes_keyring_generate_data_key,
    .encrypt_data_key = raw_aes_keyring_encrypt_data_key,
    .decrypt_data_key = raw_aes_keyring_decrypt_data_key
};

struct aws_cryptosdk_keyring * aws_cryptosdk_raw_aes_keyring_new(struct aws_allocator * alloc,
                                                       const uint8_t * master_key_id,
                                                       size_t master_key_id_len,
                                                       const uint8_t * provider_id,
                                                       size_t provider_id_len,
                                                       const uint8_t * raw_key_bytes,
                                                       enum aws_cryptosdk_aes_key_len key_len) {
    struct raw_aes_keyring * kr = aws_mem_acquire(alloc, sizeof(struct raw_aes_keyring));
    if (!kr) return NULL;
    memset(kr, 0, sizeof(struct raw_aes_keyring));

    kr->master_key_id = aws_string_new_from_array(alloc, master_key_id, master_key_id_len);
    if (!kr->master_key_id) goto oom_err;

    kr->provider_id = aws_string_new_from_array(alloc, provider_id, provider_id_len);
    if (!kr->provider_id) goto oom_err;

    kr->raw_key = aws_string_new_from_array(alloc, raw_key_bytes, key_len);
    if (!kr->raw_key) goto oom_err;

    kr->vt = &raw_aes_keyring_vt;
    kr->alloc = alloc;
    return (struct aws_cryptosdk_keyring *)kr;

oom_err:
    aws_string_destroy((void *)kr->master_key_id);
    aws_string_destroy((void *)kr->provider_id);
    aws_mem_release(alloc, kr);
    return NULL;
}
