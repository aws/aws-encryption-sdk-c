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
#include <stdio.h>
#include <stdlib.h>
#include <aws/cryptosdk/private/raw_aes_mk.h>
#include "raw_aes_mk_test_vectors.h"

const uint8_t test_vector_master_key_id[] = "asdfhasiufhiasuhviawurhgiuawrhefiuawhf";
const uint8_t test_vector_provider_id[] = "static-random";
const uint8_t test_vector_wrapping_key[] =
{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

struct aws_cryptosdk_edk build_test_edk(const uint8_t * edk_bytes, size_t edk_len, const uint8_t * iv) {
    static const uint8_t edk_provider_prefix[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c"; // IV length in bytes

    struct aws_cryptosdk_edk edk;
    edk.enc_data_key = aws_byte_buf_from_array(edk_bytes, edk_len);
    edk.provider_id = aws_byte_buf_from_array(test_vector_provider_id, sizeof(test_vector_provider_id) - 1);

    int ret = aws_byte_buf_init(aws_default_allocator(), &edk.provider_info, sizeof(edk_provider_prefix) - 1 + RAW_AES_MK_IV_LEN);
    if (ret != AWS_OP_SUCCESS) {
        fprintf(stderr, "\nTest failed at %s:%d\n", __FILE__, __LINE__);
        abort();
    }
    memcpy(edk.provider_info.buffer, edk_provider_prefix, sizeof(edk_provider_prefix) - 1);
    memcpy(edk.provider_info.buffer + sizeof(edk_provider_prefix) - 1, iv, RAW_AES_MK_IV_LEN);
    edk.provider_info.len = edk.provider_info.capacity;
    return edk;
}

static void add_pairs_to_hash_table(struct aws_hash_table * enc_context,
                                    const struct aws_string ** keys,
                                    const struct aws_string ** vals,
                                    size_t num_pairs) {
    for (int idx = 0; idx < num_pairs; ++idx) {
        struct aws_hash_element * elem;
        if (aws_hash_table_create(enc_context, (void *)keys[idx], &elem, NULL)) {
            fprintf(stderr, "\nTest failed at %s:%d\n", __FILE__, __LINE__);
            abort();
        }
        elem->value = (void *)vals[idx];
    }
}

// Test vector 0: de/encrypt_data_key_enpty_enc_context
static const uint8_t tv_0_data_key[] =
{0xdd, 0xc2, 0xf6, 0x5f, 0x96, 0xa2, 0xda, 0x96, 0x86, 0xea, 0xd6, 0x58, 0xfe, 0xe9, 0xc0, 0xc3,
 0xb6, 0xd4, 0xb1, 0x92, 0xf2, 0xba, 0x50, 0x93, 0x21, 0x97, 0x62, 0xab, 0x7d, 0x25, 0x9f, 0x2c};

static const uint8_t tv_0_iv[] =
{0xbe, 0xa0, 0xfb, 0xd0, 0x0e, 0xee, 0x0d, 0x94, 0xd9, 0xb1, 0xb3, 0x93};

static const uint8_t tv_0_edk_bytes[] =
{0x54, 0x2b, 0xf0, 0xdc, 0x35, 0x20, 0x07, 0x38, 0xe4, 0x9e, 0x34, 0xfa, 0xa6, 0xbf, 0x11, 0xed,
 0x45, 0x40, 0x97, 0xfd, 0xb8, 0xe3, 0x36, 0x75, 0x5c, 0x03, 0xbb, 0x9f, 0xa4, 0x42, 0x9e, 0x66,
 0x44, 0x7c, 0x39, 0xf7, 0x7f, 0xfe, 0xbc, 0xa5, 0x98, 0x70, 0xe9, 0xa8, 0xc9, 0xb5, 0x7f, 0x6f};

static void tv_0_enc_context_builder(struct aws_hash_table * enc_context) {}

// Test vector 1: de/encrypt_data_key_unsigned_comparison_192
static const uint8_t tv_1_data_key[] =
{0xfa, 0xce, 0xa0, 0x72, 0x10, 0x80, 0x80, 0x7a, 0x9d, 0xdb, 0x1f, 0x9a, 0x8d, 0x68, 0xee, 0xb0,
 0x86, 0xb5, 0x45, 0xcc, 0x4d, 0x8d, 0xc5, 0x75, 0x7a, 0x36, 0xc1, 0xd2, 0x78, 0x8b, 0x01, 0x1f};

static const uint8_t tv_1_iv[] =
{0x75, 0x21, 0x9f, 0x96, 0x77, 0xaa, 0xc8, 0x9e, 0xd8, 0x53, 0x8f, 0x57};

static const uint8_t tv_1_edk_bytes[] =
{0x70, 0x73, 0x47, 0x19, 0x91, 0x77, 0x3b, 0xac, 0x64, 0x4a, 0x20, 0x0a, 0x81, 0x56, 0x8c, 0x5c,
 0x69, 0xe4, 0x62, 0x28, 0xbc, 0x6c, 0x6c, 0x6b, 0xd6, 0x3a, 0x3c, 0xfb, 0xf0, 0x80, 0xc7, 0xf1,
 0xb8, 0xee, 0xc8, 0xa1, 0x5c, 0x6c, 0xc2, 0x81, 0x3a, 0xcc, 0xd2, 0xdb, 0x52, 0x77, 0x55, 0x49};

static void tv_1_enc_context_builder(struct aws_hash_table * enc_context) {
    AWS_STATIC_STRING_FROM_LITERAL(tv_1_key_1, "aaaaaaaa\xc2\x80");
    AWS_STATIC_STRING_FROM_LITERAL(tv_1_val_1, "AAAAAAAA");
    AWS_STATIC_STRING_FROM_LITERAL(tv_1_key_2, "aaaaaaaa\x7f");
    AWS_STATIC_STRING_FROM_LITERAL(tv_1_val_2, "BBBBBBBB");
    const struct aws_string * tv_1_keys[] = {tv_1_key_1, tv_1_key_2};
    const struct aws_string * tv_1_vals[] = {tv_1_val_1, tv_1_val_2};
    add_pairs_to_hash_table(enc_context,
                            tv_1_keys,
                            tv_1_vals,
                            sizeof(tv_1_keys)/sizeof(const struct aws_string *));
}

static const uint8_t tv_2_data_key[] =
{0x6d, 0x3f, 0xf7, 0xe9, 0x0e, 0xe4, 0x81, 0x09, 0x87, 0x8f, 0x37, 0xd9, 0x6a, 0x21, 0xe5, 0xf8};

static const uint8_t tv_2_iv[] =
{0x8e, 0x2b, 0xfd, 0x25, 0x66, 0x5a, 0x1c, 0x0d, 0x0d, 0x4a, 0x49, 0x14};

static const uint8_t tv_2_edk_bytes[] =
{0x29, 0x09, 0x38, 0x89, 0xe4, 0x4e, 0x1c, 0xdc, 0xf0, 0x4d, 0x0b, 0xa1, 0xe4, 0x52, 0xd5, 0x77,
 0x53, 0xf8, 0x23, 0x7a, 0x52, 0xd9, 0xca, 0xa8, 0x53, 0x6e, 0xf9, 0xcb, 0xae, 0x22, 0x63, 0xae};

static void tv_2_enc_context_builder(struct aws_hash_table * enc_context) {
    AWS_STATIC_STRING_FROM_LITERAL(key, "correct");
    AWS_STATIC_STRING_FROM_LITERAL(val, "context");
    add_pairs_to_hash_table(enc_context, &key, &val, 1);
}

struct raw_aes_mk_test_vector test_vectors[] = {
    {.raw_key_len = AWS_CRYPTOSDK_AES_256,
     .alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
     .data_key = tv_0_data_key,
     .data_key_len = sizeof(tv_0_data_key),
     .iv = tv_0_iv,
     .edk_bytes = tv_0_edk_bytes,
     .edk_bytes_len = sizeof(tv_0_edk_bytes),
     .ec_builder = tv_0_enc_context_builder
    },
    {.raw_key_len = AWS_CRYPTOSDK_AES_192,
     .alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
     .data_key = tv_1_data_key,
     .data_key_len = sizeof(tv_1_data_key),
     .iv = tv_1_iv,
     .edk_bytes = tv_1_edk_bytes,
     .edk_bytes_len = sizeof(tv_1_edk_bytes),
     .ec_builder = tv_1_enc_context_builder
    },
    {.raw_key_len = AWS_CRYPTOSDK_AES_128,
     .alg = AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
     .data_key = tv_2_data_key,
     .data_key_len = sizeof(tv_2_data_key),
     .iv = tv_2_iv,
     .edk_bytes = tv_2_edk_bytes,
     .edk_bytes_len = sizeof(tv_2_edk_bytes),
     .ec_builder = tv_2_enc_context_builder
    }
};

struct aws_cryptosdk_edk edk_from_test_vector(int idx) {
    return build_test_edk(test_vectors[idx].edk_bytes, test_vectors[idx].edk_bytes_len, test_vectors[idx].iv);
}
