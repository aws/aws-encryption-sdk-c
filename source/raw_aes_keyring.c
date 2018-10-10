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
#include <aws/cryptosdk/materials.h>

static int serialize_aad_init(struct aws_allocator *alloc,
                              struct aws_byte_buf *aad,
                              const struct aws_hash_table *enc_context) {
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

int aws_cryptosdk_serialize_key_name_init(struct aws_allocator * alloc,
                                               struct aws_byte_buf * output,
                                               const struct aws_string * key_name,
                                               const uint8_t * iv) {
    size_t serialized_len = key_name->len + RAW_AES_KR_IV_LEN + 8; // 4 for tag len, 4 for iv len
    if (aws_byte_buf_init(alloc, output, serialized_len)) {
        return AWS_OP_ERR;
    }
    output->len = output->capacity;
    struct aws_byte_cursor cur = aws_byte_cursor_from_buf(output);
    if (!aws_byte_cursor_write_from_whole_string(&cur, key_name)) goto write_err;
    if (!aws_byte_cursor_write_be32(&cur, RAW_AES_KR_TAG_LEN * 8)) goto write_err;
    if (!aws_byte_cursor_write_be32(&cur, RAW_AES_KR_IV_LEN)) goto write_err;
    if (!aws_byte_cursor_write(&cur, iv, RAW_AES_KR_IV_LEN)) goto write_err;

    return AWS_OP_SUCCESS;

write_err:
    // We should never get here, because buffer was allocated locally to be long enough.
    aws_byte_buf_clean_up(output);
    return aws_raise_error(AWS_ERROR_UNKNOWN);
}

bool aws_cryptosdk_parse_key_name(struct aws_cryptosdk_keyring * kr,
                                       struct aws_byte_buf * iv,
                                       const struct aws_byte_buf * key_name) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;
    size_t key_name_len = self->key_name->len;
    size_t serialized_len = key_name_len + RAW_AES_KR_IV_LEN + 8;
    if (serialized_len != key_name->len) return false;

    struct aws_byte_cursor cur = aws_byte_cursor_from_buf(key_name);

    struct aws_byte_cursor keyname = aws_byte_cursor_advance_nospec(&cur, key_name_len);
    if (!keyname.ptr) goto READ_ERR;
    if (!aws_string_eq_byte_cursor(self->key_name, &keyname)) return false;

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

int aws_cryptosdk_raw_aes_keyring_encrypt_data_key_with_iv(struct aws_cryptosdk_keyring *kr,
                                                           struct aws_allocator *request_alloc,
                                                           const struct aws_byte_buf *unencrypted_data_key,
                                                           struct aws_array_list *edks,
                                                           const struct aws_hash_table *enc_context,
                                                           enum aws_cryptosdk_alg_id alg,
                                                           const uint8_t *iv) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;

    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(alg);
    size_t data_key_len = props->data_key_len;

    struct aws_byte_buf aad;
    if (serialize_aad_init(request_alloc, &aad, enc_context)) {
        return AWS_OP_ERR;
    }

    struct aws_cryptosdk_edk edk = {{0}};
    /* Encrypted data key bytes same length as unencrypted data key in GCM.
     * cipher_text field also includes tag afterward.
     */
    if (aws_byte_buf_init(request_alloc, &edk.cipher_text, data_key_len + RAW_AES_KR_TAG_LEN)) {
        aws_byte_buf_clean_up(&aad);
        return AWS_OP_ERR;
    }
    struct aws_byte_buf cipher_text = aws_byte_buf_from_array(edk.cipher_text.buffer, data_key_len);
    struct aws_byte_buf tag = aws_byte_buf_from_array(edk.cipher_text.buffer + data_key_len, RAW_AES_KR_TAG_LEN);
    if (aws_cryptosdk_aes_gcm_encrypt(&cipher_text,
                                      &tag,
                                      aws_byte_cursor_from_buf(unencrypted_data_key),
                                      aws_byte_cursor_from_array(iv, RAW_AES_KR_IV_LEN),
                                      aws_byte_cursor_from_buf(&aad),
                                      self->raw_key)) goto err;
    edk.cipher_text.len = edk.cipher_text.capacity;

    if (aws_cryptosdk_serialize_key_name_init(request_alloc, &edk.key_name, self->key_name, iv))
        goto err;

    if (aws_byte_buf_init(request_alloc, &edk.name_space, self->name_space->len)) goto err;
    edk.name_space.len = edk.name_space.capacity;
    struct aws_byte_cursor name_space = aws_byte_cursor_from_buf(&edk.name_space);
    if (!aws_byte_cursor_write_from_whole_string(&name_space, self->name_space)) goto err;

    if (aws_array_list_push_back(edks, &edk)) goto err;

    aws_byte_buf_clean_up(&aad);
    return AWS_OP_SUCCESS;

err:
    aws_cryptosdk_edk_clean_up(&edk);
    aws_byte_buf_clean_up(&aad);
    return AWS_OP_ERR;
}

static int raw_aes_keyring_on_encrypt(struct aws_cryptosdk_keyring * kr,
                                      struct aws_allocator *request_alloc,
                                      struct aws_byte_buf *unencrypted_data_key,
                                      struct aws_array_list *edks,
                                      const struct aws_hash_table *enc_context,
                                      enum aws_cryptosdk_alg_id alg) {
    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(alg);
    size_t data_key_len = props->data_key_len;

    uint8_t iv[RAW_AES_KR_IV_LEN];
    if (aws_cryptosdk_genrandom(iv, RAW_AES_KR_IV_LEN)) return AWS_OP_ERR;

    bool generated_new_data_key = false;
    if (!unencrypted_data_key->buffer) {
        if (aws_byte_buf_init(request_alloc, unencrypted_data_key, data_key_len)) return AWS_OP_ERR;

        if (aws_cryptosdk_genrandom(unencrypted_data_key->buffer, data_key_len)) {
            aws_byte_buf_clean_up(unencrypted_data_key);
            return AWS_OP_ERR;
        }
        generated_new_data_key = true;
        unencrypted_data_key->len = unencrypted_data_key->capacity;
    }

    int ret = aws_cryptosdk_raw_aes_keyring_encrypt_data_key_with_iv(kr,
                                                                     request_alloc,
                                                                     unencrypted_data_key,
                                                                     edks,
                                                                     enc_context,
                                                                     alg,
                                                                     iv);
    if (ret && generated_new_data_key) {
        aws_byte_buf_clean_up(unencrypted_data_key);
    }
    return ret;
}


static int raw_aes_keyring_on_decrypt(struct aws_cryptosdk_keyring * kr,
                                      struct aws_allocator *request_alloc,
                                      struct aws_byte_buf *unencrypted_data_key,
                                      const struct aws_array_list *edks,
                                      const struct aws_hash_table *enc_context,
                                      enum aws_cryptosdk_alg_id alg) {
    struct raw_aes_keyring *self = (struct raw_aes_keyring *)kr;

    struct aws_byte_buf aad;
    if (serialize_aad_init(request_alloc, &aad, enc_context)) {
        return AWS_OP_ERR;
    }

    size_t num_edks = aws_array_list_length(edks);

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
    size_t data_key_len = props->data_key_len;

    if (aws_byte_buf_init(request_alloc, unencrypted_data_key, props->data_key_len)) {
        aws_byte_buf_clean_up(&aad);
        return AWS_OP_ERR;
    }

    for (size_t edk_idx = 0; edk_idx < num_edks; ++edk_idx) {
        const struct aws_cryptosdk_edk *edk;
        if (aws_array_list_get_at_ptr(edks, (void **)&edk, edk_idx)) {
            aws_byte_buf_clean_up(&aad);
            return AWS_OP_ERR;
        }
        if (!edk->name_space.len || !edk->key_name.len || !edk->cipher_text.len) continue;

        if (!aws_string_eq_byte_buf(self->name_space, &edk->name_space)) continue;

        struct aws_byte_buf iv;
        if (!aws_cryptosdk_parse_key_name(kr, &iv, &edk->key_name)) continue;

        const struct aws_byte_buf *cipher_text = &edk->cipher_text;

        /* Using GCM, so encrypted and unencrypted data key have same length, i.e. data_key_len.
         * cipher_text->buffer holds encrypted data key followed by GCM tag.
         */
        if (data_key_len + RAW_AES_KR_TAG_LEN != cipher_text->len) continue;

        if (aws_cryptosdk_aes_gcm_decrypt(unencrypted_data_key,
                                          aws_byte_cursor_from_array(cipher_text->buffer, data_key_len),
                                          aws_byte_cursor_from_array(cipher_text->buffer + data_key_len,
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
            goto success;
        }
    }
    // None of the EDKs worked, clean up unencrypted data key buffer and return success per materials.h
    aws_byte_buf_clean_up(unencrypted_data_key);

success:
    aws_byte_buf_clean_up(&aad);
    return AWS_OP_SUCCESS;
}

static void raw_aes_keyring_destroy(struct aws_cryptosdk_keyring * kr) {
    struct raw_aes_keyring * self = (struct raw_aes_keyring *)kr;
    aws_string_destroy((void *)self->key_name);
    aws_string_destroy((void *)self->name_space);
    aws_string_destroy_secure((void *)self->raw_key);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_keyring_vt raw_aes_keyring_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "raw AES keyring",
    .destroy = raw_aes_keyring_destroy,
    .on_encrypt = raw_aes_keyring_on_encrypt,
    .on_decrypt = raw_aes_keyring_on_decrypt
};

struct aws_cryptosdk_keyring * aws_cryptosdk_raw_aes_keyring_new(struct aws_allocator * alloc,
                                                                 const uint8_t * key_name,
                                                                 size_t key_name_len,
                                                                 const uint8_t * name_space,
                                                                 size_t name_space_len,
                                                                 const uint8_t * raw_key_bytes,
                                                                 enum aws_cryptosdk_aes_key_len key_len) {
    struct raw_aes_keyring * kr = aws_mem_acquire(alloc, sizeof(struct raw_aes_keyring));
    if (!kr) return NULL;
    memset(kr, 0, sizeof(struct raw_aes_keyring));

    aws_cryptosdk_keyring_base_init(&kr->base, &raw_aes_keyring_vt);

    kr->key_name = aws_string_new_from_array(alloc, key_name, key_name_len);
    if (!kr->key_name) goto oom_err;

    kr->name_space = aws_string_new_from_array(alloc, name_space, name_space_len);
    if (!kr->name_space) goto oom_err;

    kr->raw_key = aws_string_new_from_array(alloc, raw_key_bytes, key_len);
    if (!kr->raw_key) goto oom_err;

    kr->alloc = alloc;
    return (struct aws_cryptosdk_keyring *)kr;

oom_err:
    aws_string_destroy((void *)kr->key_name);
    aws_string_destroy((void *)kr->name_space);
    aws_mem_release(alloc, kr);
    return NULL;
}
