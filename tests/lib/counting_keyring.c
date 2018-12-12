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

struct counting_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_allocator *alloc;
};

static inline struct aws_byte_buf aws_string_to_buf(const struct aws_string *s) {
    return aws_byte_buf_from_array(aws_string_bytes(s), s->len);
}

AWS_STATIC_STRING_FROM_LITERAL(prov_name, "test_counting");
AWS_STATIC_STRING_FROM_LITERAL(prov_info, "test_counting_prov_info");
AWS_STATIC_STRING_FROM_LITERAL(expected_edk, "\x40\x41\x42\x43\x44");

static int set_edk(struct aws_allocator *alloc, struct aws_cryptosdk_edk *edk) {
    struct aws_byte_buf src;

    src = aws_string_to_buf(prov_name);
    if (aws_byte_buf_init_copy(&edk->provider_id, alloc, &src))
        return AWS_OP_ERR;
    src = aws_string_to_buf(prov_info);
    if (aws_byte_buf_init_copy(&edk->provider_info, alloc, &src))
        return AWS_OP_ERR;
    src = aws_string_to_buf(expected_edk);
    if (aws_byte_buf_init_copy(&edk->enc_data_key, alloc, &src))
        return AWS_OP_ERR;

    return AWS_OP_SUCCESS;
}

static inline bool is_counting_edk(const struct aws_cryptosdk_edk *edk) {
    return (
        aws_string_eq_byte_buf(prov_name, &edk->provider_id) &&
        aws_string_eq_byte_buf(prov_info, &edk->provider_info) &&
        aws_string_eq_byte_buf(expected_edk, &edk->enc_data_key)
    );
}

static int counting_keyring_on_encrypt(struct aws_cryptosdk_keyring *kr,
                                       struct aws_allocator *request_alloc,
                                       struct aws_byte_buf *unencrypted_data_key,
                                       struct aws_array_list *keyring_trace,
                                       struct aws_array_list *edks,
                                       const struct aws_hash_table *enc_context,
                                       enum aws_cryptosdk_alg_id alg) {
    (void)enc_context;
    (void)kr;

    const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(alg);
    uint32_t flags = AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY;

    if (unencrypted_data_key->buffer) {
        if (unencrypted_data_key->len != props->data_key_len) {
            // We can't encrypt arbitrary keys with this KR
            return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
        }
        for (size_t byte_idx = 0 ; byte_idx < unencrypted_data_key->len ; ++byte_idx) {
            if (unencrypted_data_key->buffer[byte_idx] != (uint8_t)byte_idx) {
                // Wrong key bytes
                return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
            }
        }
    } else {
        if (aws_byte_buf_init(unencrypted_data_key, request_alloc, props->data_key_len)) {
            return AWS_OP_ERR;
        }
        unencrypted_data_key->len = props->data_key_len;

        for (size_t i = 0; i < props->data_key_len; i++) {
            unencrypted_data_key->buffer[i] = (uint8_t)i;
        }
        flags |= AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY;
    }

    struct aws_cryptosdk_edk edk;
    if (set_edk(request_alloc, &edk)) {
        return AWS_OP_ERR;
    }

    aws_cryptosdk_keyring_trace_add_record(request_alloc,
                                           keyring_trace,
                                           prov_name,
                                           prov_info,
                                           flags);
    return aws_array_list_push_back(edks, &edk);
}

static int counting_keyring_on_decrypt(struct aws_cryptosdk_keyring *kr,
                                       struct aws_allocator *request_alloc,
                                       struct aws_byte_buf *unencrypted_data_key,
                                       struct aws_array_list *keyring_trace,
                                       const struct aws_array_list *edks,
                                       const struct aws_hash_table *enc_context,
                                       enum aws_cryptosdk_alg_id alg) {
    (void)enc_context;
    (void)kr;
    
    // verify there is at least one EDK with the right signature present
    size_t num_keys = aws_array_list_length(edks);
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (aws_array_list_get_at_ptr(edks, (void **)&edk, key_idx)) return AWS_OP_ERR;
        if (is_counting_edk(edk)) {
            const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);

            if (aws_byte_buf_init(unencrypted_data_key, request_alloc, props->data_key_len)) {
                return AWS_OP_ERR;
            }

            unencrypted_data_key->len = props->data_key_len;
            for (size_t i = 0; i < unencrypted_data_key->len; i++) {
                unencrypted_data_key->buffer[i] = (uint8_t)i;
            }
            aws_cryptosdk_keyring_trace_add_record(request_alloc,
                                                   keyring_trace,
                                                   prov_name,
                                                   prov_info,
                                                   AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY);
            return AWS_OP_SUCCESS;
        }
    }
    /* We were not able to decrypt any of the EDKs using this master key. This is normal behavior,
     * so return success without allocating an unencrypted data key.
     */
    return AWS_OP_SUCCESS;
}

static void counting_keyring_destroy(struct aws_cryptosdk_keyring * kr) {
    struct counting_keyring *self = (struct counting_keyring *)kr;
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_keyring_vt counting_keyring_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_keyring_vt),
    .name = "TEST: counting keyring",
    .destroy = counting_keyring_destroy,
    .on_encrypt = counting_keyring_on_encrypt,
    .on_decrypt = counting_keyring_on_decrypt
};


struct aws_cryptosdk_keyring *aws_cryptosdk_counting_keyring_new(struct aws_allocator *alloc) {
    struct counting_keyring *kr = aws_mem_acquire(alloc, sizeof(struct counting_keyring));
    if (!kr) return NULL;
    aws_cryptosdk_keyring_base_init(&kr->base, &counting_keyring_vt);
    kr->alloc = alloc;
    return (struct aws_cryptosdk_keyring *)kr;
}
