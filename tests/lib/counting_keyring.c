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
#include <stdbool.h>
#include "counting_keyring.h"
#include <aws/cryptosdk/cipher.h>
#include <aws/common/string.h>
#include <aws/common/byte_buf.h>

struct counting_keyring {const struct aws_cryptosdk_keyring_vt * vt;};

static inline struct aws_byte_buf aws_string_to_buf(const struct aws_string *s) {
    return aws_byte_buf_from_array(aws_string_bytes(s), s->len);
}

AWS_STATIC_STRING_FROM_LITERAL(prov_name, "test_counting");
AWS_STATIC_STRING_FROM_LITERAL(prov_info, "test_counting_prov_info");
AWS_STATIC_STRING_FROM_LITERAL(expected_edk, "\x40\x41\x42\x43\x44");

static int set_edk(struct aws_allocator *alloc, struct aws_cryptosdk_edk * edk) {
    struct aws_byte_buf src;

    src = aws_string_to_buf(prov_name);
    if (aws_byte_buf_init_copy(alloc, &edk->provider_id, &src))
        return AWS_OP_ERR;
    src = aws_string_to_buf(prov_info);
    if (aws_byte_buf_init_copy(alloc, &edk->provider_info, &src))
        return AWS_OP_ERR;
    src = aws_string_to_buf(expected_edk);
    if (aws_byte_buf_init_copy(alloc, &edk->enc_data_key, &src))
        return AWS_OP_ERR;

    return AWS_OP_SUCCESS;
}

static inline bool str_eq_buf(const struct aws_string *s, const struct aws_byte_buf *buf) {
    return s->len == buf->len && !memcmp(aws_string_bytes(s), buf->buffer, s->len);
}

static inline bool is_counting_edk(const struct aws_cryptosdk_edk * edk) {
    return (
        str_eq_buf(prov_name, &edk->provider_id) &&
        str_eq_buf(prov_info, &edk->provider_info) &&
        str_eq_buf(expected_edk, &edk->enc_data_key)
    );
}

static int counting_keyring_generate_data_key(
    struct aws_cryptosdk_keyring * kr,
    struct aws_cryptosdk_encryption_materials * enc_mat
) {
    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(enc_mat->alg);
    if (aws_byte_buf_init(enc_mat->alloc, &enc_mat->unencrypted_data_key, props->data_key_len)) {
        return AWS_OP_ERR;
    }

    enc_mat->unencrypted_data_key.len = aws_cryptosdk_alg_props(enc_mat->alg)->data_key_len;
    for (size_t i = 0; i < enc_mat->unencrypted_data_key.len; i++) {
        enc_mat->unencrypted_data_key.buffer[i] = (uint8_t)i;
    }

    struct aws_cryptosdk_edk edk;
    if (set_edk(enc_mat->alloc, &edk)) {
        return AWS_OP_ERR;
    }

    return aws_array_list_push_back(&enc_mat->encrypted_data_keys, &edk);
}

static int counting_keyring_encrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                    struct aws_cryptosdk_encryption_materials * enc_mat
) {
    struct aws_byte_buf *unencrypted_data_key = &enc_mat->unencrypted_data_key;
    if (unencrypted_data_key->len != aws_cryptosdk_alg_props(enc_mat->alg)->data_key_len) {
        // We can't encrypt arbitrary keys with this KR
        return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
    }

    for (size_t byte_idx = 0 ; byte_idx < unencrypted_data_key->len ; ++byte_idx) {
        if (unencrypted_data_key->buffer[byte_idx] != (uint8_t)byte_idx) {
            // Wrong key bytes
            return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
        }
    }

    struct aws_cryptosdk_edk edk;
    if (set_edk(enc_mat->alloc, &edk)) {
        return AWS_OP_ERR;
    }

    return aws_array_list_push_back(&enc_mat->encrypted_data_keys, &edk);
}

static int counting_keyring_decrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                        struct aws_cryptosdk_decryption_materials * dec_mat,
                                        const struct aws_cryptosdk_decryption_request * req
) {
    const struct aws_array_list * edks = &req->encrypted_data_keys;
    // verify there is at least one EDK with the right signature present
    size_t num_keys = aws_array_list_length(edks);
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (aws_array_list_get_at_ptr(edks, (void **)&edk, key_idx)) return AWS_OP_ERR;
        if (is_counting_edk(edk)) {
            const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(dec_mat->alg);

            if (aws_byte_buf_init(dec_mat->alloc, &dec_mat->unencrypted_data_key, props->data_key_len)) {
                return AWS_OP_ERR;
            }

            dec_mat->unencrypted_data_key.len = props->data_key_len;
            for (size_t i = 0; i < dec_mat->unencrypted_data_key.len; i++) {
                dec_mat->unencrypted_data_key.buffer[i] = (uint8_t)i;
            }

            return AWS_OP_SUCCESS;
        }
    }
    return AWS_OP_ERR;
}

static void counting_keyring_destroy(struct aws_cryptosdk_keyring * kr) {}

static const struct aws_cryptosdk_keyring_vt counting_keyring_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "TEST: counting keyring",
    .destroy = counting_keyring_destroy,
    .generate_data_key = counting_keyring_generate_data_key,
    .encrypt_data_key = counting_keyring_encrypt_data_key,
    .decrypt_data_key = counting_keyring_decrypt_data_key
};

static struct counting_keyring counting_keyring_singleton = {.vt = &counting_keyring_vt};

struct aws_cryptosdk_keyring * aws_cryptosdk_counting_keyring() {
    return (struct aws_cryptosdk_keyring *)&counting_keyring_singleton;
}
