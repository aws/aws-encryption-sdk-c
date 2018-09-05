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
#include "zero_keyring.h"
#include <aws/cryptosdk/cipher.h>

struct zero_keyring {const struct aws_cryptosdk_keyring_vt * vt;};

static const char * literally_null = "null";

void aws_cryptosdk_literally_null_edk(struct aws_cryptosdk_edk * edk) {
    edk->provider_id = aws_byte_buf_from_c_str(literally_null);
    edk->provider_info = aws_byte_buf_from_c_str(literally_null);
    edk->enc_data_key = aws_byte_buf_from_c_str(literally_null);
}

static bool buf_equals_c_string(const struct aws_byte_buf *buf, const char *cstr) {
    size_t len = strlen(cstr);
    return len == buf->len && !memcmp(buf->buffer, cstr, len);
}

static inline bool is_literally_null_edk(const struct aws_cryptosdk_edk * edk) {
    if (buf_equals_c_string(&edk->provider_id, literally_null) &&
        buf_equals_c_string(&edk->provider_info, literally_null) &&
        buf_equals_c_string(&edk->enc_data_key, literally_null)
    ) return true;

    // Some older test vectors use "zero-key" / "provider info" / "\0" as their test data

    if (buf_equals_c_string(&edk->provider_id, "zero-key") &&
        buf_equals_c_string(&edk->provider_info, "provider info") &&
        edk->enc_data_key.len == 1 && edk->enc_data_key.buffer[0] == 0
    ) return true;

    return false;
}

static int zero_keyring_generate_or_encrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                                     struct aws_byte_buf * unencrypted_data_key,
                                                     struct aws_array_list * edks,
                                                     const struct aws_hash_table * enc_context,
                                                     enum aws_cryptosdk_alg_id alg) {
    (void)kr;
    (void)enc_context;
    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(alg);

    if (unencrypted_data_key->buffer) {
        if (unencrypted_data_key->len != props->data_key_len) {
            // We can't encrypt arbitrary keys with this KR
            return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
        }
        for (size_t byte_idx = 0 ; byte_idx < unencrypted_data_key->len ; ++byte_idx) {
            if (unencrypted_data_key->buffer[byte_idx]) {
                // Zero KR only encrypts the all zero data key
                return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
            }
        }
    } else {
        if (aws_byte_buf_init(aws_default_allocator(), unencrypted_data_key, props->data_key_len)) {
            return AWS_OP_ERR;
        }
        aws_byte_buf_secure_zero(unencrypted_data_key);
        unencrypted_data_key->len = unencrypted_data_key->capacity;
    }

    struct aws_cryptosdk_edk edk;
    aws_cryptosdk_literally_null_edk(&edk);
    return aws_array_list_push_back(edks, &edk);
}

static int zero_keyring_decrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                         struct aws_byte_buf * unencrypted_data_key,
                                         const struct aws_array_list * edks,
                                         const struct aws_hash_table * enc_context,
                                         enum aws_cryptosdk_alg_id alg) {
    (void)kr;
    (void)enc_context;

    // verify there is at least one EDK with length zero present
    size_t num_keys = aws_array_list_length(edks);
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (aws_array_list_get_at_ptr(edks, (void **)&edk, key_idx)) return AWS_OP_ERR;
        if (is_literally_null_edk(edk)) {
            const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
            if (aws_byte_buf_init(aws_default_allocator(), unencrypted_data_key, props->data_key_len)) {
                return AWS_OP_ERR;
            }
            aws_byte_buf_secure_zero(unencrypted_data_key);
            unencrypted_data_key->len = unencrypted_data_key->capacity;
            return AWS_OP_SUCCESS;
        }
    }
    /* We were not able to decrypt any of the EDKs using this master key. This is normal behavior,
     * so return success without allocating an unencrypted data key.
     */
    return AWS_OP_SUCCESS;
}

static void zero_keyring_destroy(struct aws_cryptosdk_keyring * kr) {
    (void)kr;
}

static const struct aws_cryptosdk_keyring_vt zero_keyring_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "zero keyring",
    .destroy = zero_keyring_destroy,
    .generate_or_encrypt_data_key = zero_keyring_generate_or_encrypt_data_key,
    .decrypt_data_key = zero_keyring_decrypt_data_key
};

static struct zero_keyring zero_keyring_singleton = {.vt = &zero_keyring_vt};
static struct aws_cryptosdk_keyring * kr = (struct aws_cryptosdk_keyring *) &zero_keyring_singleton;

struct aws_cryptosdk_keyring * aws_cryptosdk_zero_keyring_new() {return kr;}
