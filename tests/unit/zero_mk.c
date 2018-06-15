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
#include "zero_mk.h"
#include <aws/cryptosdk/cipher.h> // aws_cryptosdk_secure_zero_buf

struct zero_mk {const struct aws_cryptosdk_mk_vt * vt;};

const char * literally_null = "null";

void aws_cryptosdk_literally_null_edk(struct aws_cryptosdk_edk * edk) {
    edk->provider_id = aws_byte_buf_from_c_str(literally_null);
    edk->provider_info = aws_byte_buf_from_c_str(literally_null);
    edk->enc_data_key = aws_byte_buf_from_c_str(literally_null);
}

static inline bool is_literally_null_edk(const struct aws_cryptosdk_edk * edk) {
    size_t len = strlen(literally_null);
    return edk->provider_id.len == len && !memcmp(edk->provider_id.buffer, literally_null, len) &&
        edk->provider_info.len == len && !memcmp(edk->provider_info.buffer, literally_null, len) &&
        edk->enc_data_key.len == len && !memcmp(edk->enc_data_key.buffer, literally_null, len);
}

static int zero_mk_generate_data_key(struct aws_cryptosdk_mk * mk,
                                     struct aws_byte_buf * unencrypted_data_key,
                                     struct aws_cryptosdk_edk * edk,
                                     const struct aws_hash_table * enc_context,
                                     enum aws_cryptosdk_alg_id alg) {
    aws_cryptosdk_secure_zero_buf(unencrypted_data_key);
    unencrypted_data_key->len = unencrypted_data_key->capacity;
    aws_cryptosdk_literally_null_edk(edk);
    return AWS_OP_SUCCESS;
}

static int zero_mk_encrypt_data_key(struct aws_cryptosdk_mk * mk,
                                    struct aws_cryptosdk_edk * edk,
                                    const struct aws_byte_buf * unencrypted_data_key,
                                    const struct aws_hash_table * enc_context,
                                    enum aws_cryptosdk_alg_id alg) {
    for (size_t byte_idx = 0 ; byte_idx < unencrypted_data_key->len ; ++byte_idx) {
        if (unencrypted_data_key->buffer[byte_idx]) {
            // Zero MK only encrypts the all zero data key
            return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
        }
    }
    aws_cryptosdk_literally_null_edk(edk);
    return AWS_OP_SUCCESS;
}

static int zero_mk_decrypt_data_key(struct aws_cryptosdk_mk * mk,
                                    struct aws_byte_buf * unencrypted_data_key,
                                    const struct aws_array_list * edks,
                                    const struct aws_hash_table * enc_context,
                                    enum aws_cryptosdk_alg_id alg) {
    // verify there is at least one EDK with length zero present
    size_t num_keys = edks->length;
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (aws_array_list_get_at_ptr(edks, (void **)&edk, key_idx)) return AWS_OP_ERR;
        if (is_literally_null_edk(edk)) {
            aws_cryptosdk_secure_zero_buf(unencrypted_data_key);
            unencrypted_data_key->len = unencrypted_data_key->capacity;
            return AWS_OP_SUCCESS;
        }
    }
    return AWS_OP_ERR;
}

static void zero_mk_destroy(struct aws_cryptosdk_mk * mk) {}

static const struct aws_cryptosdk_mk_vt zero_mk_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_mk_vt),
    .name = "zero mk",
    .destroy = zero_mk_destroy,
    .generate_data_key = zero_mk_generate_data_key,
    .encrypt_data_key = zero_mk_encrypt_data_key,
    .decrypt_data_key = zero_mk_decrypt_data_key
};

static struct zero_mk zero_mk_singleton = {.vt = &zero_mk_vt};
static struct aws_cryptosdk_mk * mk = (struct aws_cryptosdk_mk *) &zero_mk_singleton;

struct aws_cryptosdk_mk * aws_cryptosdk_zero_mk_new() {return mk;}
