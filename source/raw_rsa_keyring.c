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
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/raw_rsa_keyring.h>
#include <aws/cryptosdk/private/utils.h>

#include <aws/common/byte_buf.h>
#include <aws/common/string.h>

struct raw_rsa_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_allocator *alloc;
    const struct aws_string *key_namespace;
    const struct aws_string *key_name;
    const struct aws_string * rsa_private_key_pem;
    const struct aws_string * rsa_public_key_pem;
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode;
};

static int encrypt_data_key(struct aws_cryptosdk_keyring *kr,
                            struct aws_allocator *request_alloc,
                            struct aws_byte_buf *unencrypted_data_key,
                            struct aws_array_list *edks) {
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;

    struct aws_cryptosdk_edk edk = { { 0 } };

    if (aws_cryptosdk_rsa_encrypt(&edk.enc_data_key,
                                  request_alloc,
                                  aws_byte_cursor_from_buf(unencrypted_data_key),
                                  self->rsa_public_key_pem,
                                  self->rsa_padding_mode)) goto err;

    if (aws_byte_buf_init(&edk.provider_id, request_alloc, self->key_namespace->len)) goto err;

    if (aws_byte_buf_init(&edk.provider_info, request_alloc, self->key_name->len)) goto err;

    if (!aws_byte_buf_write_from_whole_string(&edk.provider_id, self->key_namespace)) goto err;

    if (!aws_byte_buf_write_from_whole_string(&edk.provider_info, self->key_name)) goto err;

    if (aws_array_list_push_back(edks, &edk)) goto err;

    return AWS_OP_SUCCESS;

err:
    aws_cryptosdk_edk_clean_up(&edk);
    return AWS_OP_ERR;
}

static int raw_rsa_keyring_on_encrypt(struct aws_cryptosdk_keyring *kr,
                                      struct aws_allocator *request_alloc,
                                      struct aws_byte_buf *unencrypted_data_key,
                                      struct aws_array_list *keyring_trace,
                                      struct aws_array_list *edks,
                                      const struct aws_hash_table *enc_context,
                                      enum aws_cryptosdk_alg_id alg) {
    (void)enc_context;
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;
    if (!self->rsa_public_key_pem) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    uint32_t flags = 0;
    if (!unencrypted_data_key->buffer) {
        const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
        size_t data_key_len = props->data_key_len;

        if (aws_byte_buf_init(unencrypted_data_key, request_alloc, data_key_len)) return AWS_OP_ERR;

        if (aws_cryptosdk_genrandom(unencrypted_data_key->buffer, data_key_len)) {
            aws_byte_buf_clean_up(unencrypted_data_key);
            return AWS_OP_ERR;
        }
        flags = AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY;
        unencrypted_data_key->len = unencrypted_data_key->capacity;
    }
    int ret = encrypt_data_key(kr, request_alloc, unencrypted_data_key, edks);
    if (ret && flags) {
        aws_byte_buf_clean_up(unencrypted_data_key);
    }
    if (!ret) {
        flags |= AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY;
        aws_cryptosdk_keyring_trace_add_record(request_alloc,
                                               keyring_trace,
                                               self->key_namespace,
                                               self->key_name,
                                               flags);
    }
    return ret;
}

static int raw_rsa_keyring_on_decrypt(struct aws_cryptosdk_keyring *kr,
                                      struct aws_allocator *request_alloc,
                                      struct aws_byte_buf *unencrypted_data_key,
                                      struct aws_array_list *keyring_trace,
                                      const struct aws_array_list *edks,
                                      const struct aws_hash_table *enc_context,
                                      enum aws_cryptosdk_alg_id alg) {
    (void)enc_context;
    (void)alg;
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;
    if (!self->rsa_private_key_pem) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    size_t num_edks = aws_array_list_length(edks);

    for (size_t edk_idx = 0; edk_idx < num_edks; ++edk_idx) {
        const struct aws_cryptosdk_edk *edk;
        if (aws_array_list_get_at_ptr(edks, (void **)&edk, edk_idx)) { return AWS_OP_ERR; }

        if (!edk->provider_id.len || !edk->provider_info.len || !edk->enc_data_key.len) continue;
        if (!aws_string_eq_byte_buf(self->key_namespace, &edk->provider_id)) continue;
        if (!aws_string_eq_byte_buf(self->key_name, &edk->provider_info)) continue;

        if (aws_cryptosdk_rsa_decrypt(unencrypted_data_key,
                                      request_alloc,
                                      aws_byte_cursor_from_buf(&edk->enc_data_key),
                                      self->rsa_private_key_pem,
                                      self->rsa_padding_mode)) {
            /* We are here either because of a ciphertext mismatch
             * or because of an OpenSSL error. In either case, nothing
             * better to do than just moving on to next EDK, so clear the error code.
             */
            aws_reset_error();
        } else {
            aws_cryptosdk_keyring_trace_add_record(request_alloc,
                                                   keyring_trace,
                                                   self->key_namespace,
                                                   self->key_name,
                                                   AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY);
            return AWS_OP_SUCCESS;
        }
    }
    // None of the EDKs worked. Return success per materials.h
    return AWS_OP_SUCCESS;
}

static void raw_rsa_keyring_destroy(struct aws_cryptosdk_keyring *kr) {
    struct raw_rsa_keyring *self = (struct raw_rsa_keyring *)kr;
    aws_string_destroy((void *)self->key_name);
    aws_string_destroy((void *)self->key_namespace);
    aws_string_destroy_secure((void *)self->rsa_private_key_pem);
    aws_string_destroy_secure((void *)self->rsa_public_key_pem);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_keyring_vt raw_rsa_keyring_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "raw RSA keyring",
    .destroy = raw_rsa_keyring_destroy,
    .on_encrypt = raw_rsa_keyring_on_encrypt,
    .on_decrypt = raw_rsa_keyring_on_decrypt
};

struct aws_cryptosdk_keyring *aws_cryptosdk_raw_rsa_keyring_new(
    struct aws_allocator *alloc,
    const struct aws_string *key_namespace,
    const struct aws_string *key_name,
    const char *rsa_private_key_pem,
    const char *rsa_public_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode) {
    struct raw_rsa_keyring *kr = aws_mem_acquire(alloc, sizeof(struct raw_rsa_keyring));
    if (!kr) return NULL;
    memset(kr, 0, sizeof(struct raw_rsa_keyring));

    kr->key_name = aws_cryptosdk_string_dup(alloc, key_name);
    if (!kr->key_name) goto err;

    kr->key_namespace = aws_cryptosdk_string_dup(alloc, key_namespace);
    if (!kr->key_namespace) goto err;

    if (!rsa_private_key_pem && !rsa_public_key_pem)
    {
        aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
        goto err;
    }

    if (rsa_public_key_pem)
    {
        kr->rsa_public_key_pem = aws_string_new_from_c_str(alloc, rsa_public_key_pem);
        if (!kr->rsa_public_key_pem) goto err; 
    }

    if (rsa_private_key_pem)
    {
        kr->rsa_private_key_pem = aws_string_new_from_c_str(alloc, rsa_private_key_pem);
        if (!kr->rsa_private_key_pem) goto err; 
    }

    kr->rsa_padding_mode = rsa_padding_mode;
    kr->alloc = alloc;

    aws_cryptosdk_keyring_base_init(&kr->base, &raw_rsa_keyring_vt);

    return (struct aws_cryptosdk_keyring *)kr;

err:
    aws_string_destroy((void *)kr->key_name);
    aws_string_destroy((void *)kr->key_namespace);
    aws_mem_release(alloc, kr);
    return NULL;
}
