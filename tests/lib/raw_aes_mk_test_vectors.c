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

static const uint8_t raw_aes_mk_tv_master_key_id[] = "asdfhasiufhiasuhviawurhgiuawrhefiuawhf";
static const uint8_t raw_aes_mk_tv_provider_id[] = "static-random";
static const uint8_t raw_aes_mk_tv_wrapping_key[] =
{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

struct aws_cryptosdk_mk * raw_aes_mk_tv_new(struct aws_allocator * alloc,
                                            enum aws_cryptosdk_aes_key_len raw_key_len) {
    return aws_cryptosdk_raw_aes_mk_new(alloc,
                                        raw_aes_mk_tv_master_key_id,
                                        sizeof(raw_aes_mk_tv_master_key_id) - 1,
                                        raw_aes_mk_tv_provider_id,
                                        sizeof(raw_aes_mk_tv_provider_id) - 1,
                                        raw_aes_mk_tv_wrapping_key,
                                        raw_key_len);
}


struct aws_cryptosdk_edk build_test_edk_init(const uint8_t * edk_bytes, size_t edk_len, const uint8_t * iv) {
    static const uint8_t edk_provider_prefix[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c"; // IV length in bytes

    struct aws_cryptosdk_edk edk;
    edk.enc_data_key = aws_byte_buf_from_array(edk_bytes, edk_len);
    edk.provider_id = aws_byte_buf_from_array(raw_aes_mk_tv_provider_id, sizeof(raw_aes_mk_tv_provider_id) - 1);

    if (aws_byte_buf_init(aws_default_allocator(), &edk.provider_info, sizeof(edk_provider_prefix) - 1 + RAW_AES_MK_IV_LEN)) {
        fprintf(stderr, "\nTest failed at %s:%d\n", __FILE__, __LINE__);
        abort();
    }
    memcpy(edk.provider_info.buffer, edk_provider_prefix, sizeof(edk_provider_prefix) - 1);
    memcpy(edk.provider_info.buffer + sizeof(edk_provider_prefix) - 1, iv, RAW_AES_MK_IV_LEN);
    edk.provider_info.len = edk.provider_info.capacity;
    return edk;
}

int set_test_vector_encryption_context(struct aws_allocator * alloc,
                                       struct aws_hash_table * enc_context,
                                       const struct raw_aes_mk_test_vector * tv) {
    for (int idx = 0; idx < tv->num_ec_kv_pairs; ++idx) {
        struct aws_hash_element * elem;
        const struct aws_string * key = aws_string_from_c_str_new(alloc, tv->ec_keys[idx]);
        const struct aws_string * val = aws_string_from_c_str_new(alloc, tv->ec_vals[idx]);
        if (!key || !val || aws_hash_table_create(enc_context, (void *)key, &elem, NULL)) {
            aws_string_destroy((void *)key);
            aws_string_destroy((void *)val);
            return AWS_OP_ERR;
        }
        elem->value = (void *)val;
    }
    return AWS_OP_SUCCESS;
}

// Test vector 0: 256 bit wrapping key, 256 bit data key, empty encryption context
static const uint8_t tv_0_data_key[] =
{0xdd, 0xc2, 0xf6, 0x5f, 0x96, 0xa2, 0xda, 0x96, 0x86, 0xea, 0xd6, 0x58, 0xfe, 0xe9, 0xc0, 0xc3,
 0xb6, 0xd4, 0xb1, 0x92, 0xf2, 0xba, 0x50, 0x93, 0x21, 0x97, 0x62, 0xab, 0x7d, 0x25, 0x9f, 0x2c};

static const uint8_t tv_0_iv[] =
{0xbe, 0xa0, 0xfb, 0xd0, 0x0e, 0xee, 0x0d, 0x94, 0xd9, 0xb1, 0xb3, 0x93};

// 32 byte encrypted data key followed by 16 byte tag
static const uint8_t tv_0_edk_bytes[] =
{0x54, 0x2b, 0xf0, 0xdc, 0x35, 0x20, 0x07, 0x38, 0xe4, 0x9e, 0x34, 0xfa, 0xa6, 0xbf, 0x11, 0xed,
 0x45, 0x40, 0x97, 0xfd, 0xb8, 0xe3, 0x36, 0x75, 0x5c, 0x03, 0xbb, 0x9f, 0xa4, 0x42, 0x9e, 0x66,
 0x44, 0x7c, 0x39, 0xf7, 0x7f, 0xfe, 0xbc, 0xa5, 0x98, 0x70, 0xe9, 0xa8, 0xc9, 0xb5, 0x7f, 0x6f};


// Test vector 1: 192 bit wrapping key, 192 bit data key, unsigned comparison in enc context
static const uint8_t tv_1_data_key[] =
{0xfa, 0xce, 0xa0, 0x72, 0x10, 0x80, 0x80, 0x7a, 0x9d, 0xdb, 0x1f, 0x9a, 0x8d, 0x68, 0xee, 0xb0,
 0x86, 0xb5, 0x45, 0xcc, 0x4d, 0x8d, 0xc5, 0x75, 0x7a, 0x36, 0xc1, 0xd2, 0x78, 0x8b, 0x01, 0x1f};

static const uint8_t tv_1_iv[] =
{0x75, 0x21, 0x9f, 0x96, 0x77, 0xaa, 0xc8, 0x9e, 0xd8, 0x53, 0x8f, 0x57};

// 32 byte encrypted data key followed by 16 byte tag
static const uint8_t tv_1_edk_bytes[] =
{0x70, 0x73, 0x47, 0x19, 0x91, 0x77, 0x3b, 0xac, 0x64, 0x4a, 0x20, 0x0a, 0x81, 0x56, 0x8c, 0x5c,
 0x69, 0xe4, 0x62, 0x28, 0xbc, 0x6c, 0x6c, 0x6b, 0xd6, 0x3a, 0x3c, 0xfb, 0xf0, 0x80, 0xc7, 0xf1,
 0xb8, 0xee, 0xc8, 0xa1, 0x5c, 0x6c, 0xc2, 0x81, 0x3a, 0xcc, 0xd2, 0xdb, 0x52, 0x77, 0x55, 0x49};

static const char * tv_1_ec_keys[] = {"aaaaaaaa\xc2\x80", "aaaaaaaa\x7f"};
static const char * tv_1_ec_vals[] = {"AAAAAAAA", "BBBBBBBB"};


// Test vector 2: 128 bit wrapping key, 128 bit data key, with encryption context
static const uint8_t tv_2_data_key[] =
{0x6d, 0x3f, 0xf7, 0xe9, 0x0e, 0xe4, 0x81, 0x09, 0x87, 0x8f, 0x37, 0xd9, 0x6a, 0x21, 0xe5, 0xf8};

static const uint8_t tv_2_iv[] =
{0x8e, 0x2b, 0xfd, 0x25, 0x66, 0x5a, 0x1c, 0x0d, 0x0d, 0x4a, 0x49, 0x14};

// 16 byte encrypted data key followed by 16 byte tag
static const uint8_t tv_2_edk_bytes[] =
{0x29, 0x09, 0x38, 0x89, 0xe4, 0x4e, 0x1c, 0xdc, 0xf0, 0x4d, 0x0b, 0xa1, 0xe4, 0x52, 0xd5, 0x77,
 0x53, 0xf8, 0x23, 0x7a, 0x52, 0xd9, 0xca, 0xa8, 0x53, 0x6e, 0xf9, 0xcb, 0xae, 0x22, 0x63, 0xae};

static const char * tv_2_ec_keys[] = {"correct"};
static const char * tv_2_ec_vals[] = {"context"};

struct raw_aes_mk_test_vector raw_aes_mk_test_vectors[] = {
    {.raw_key_len = AWS_CRYPTOSDK_AES_256,
     .alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
     .data_key = tv_0_data_key,
     .data_key_len = sizeof(tv_0_data_key),
     .iv = tv_0_iv,
     .edk_bytes = tv_0_edk_bytes,
     .edk_bytes_len = sizeof(tv_0_edk_bytes),
     .ec_keys = NULL,
     .ec_vals = NULL,
     .num_ec_kv_pairs = 0
    },
    {.raw_key_len = AWS_CRYPTOSDK_AES_192,
     .alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
     .data_key = tv_1_data_key,
     .data_key_len = sizeof(tv_1_data_key),
     .iv = tv_1_iv,
     .edk_bytes = tv_1_edk_bytes,
     .edk_bytes_len = sizeof(tv_1_edk_bytes),
     .ec_keys = tv_1_ec_keys,
     .ec_vals = tv_1_ec_vals,
     .num_ec_kv_pairs = sizeof(tv_1_ec_keys)/sizeof(const uint8_t *)
    },
    {.raw_key_len = AWS_CRYPTOSDK_AES_128,
     .alg = AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
     .data_key = tv_2_data_key,
     .data_key_len = sizeof(tv_2_data_key),
     .iv = tv_2_iv,
     .edk_bytes = tv_2_edk_bytes,
     .edk_bytes_len = sizeof(tv_2_edk_bytes),
     .ec_keys = tv_2_ec_keys,
     .ec_vals = tv_2_ec_vals,
     .num_ec_kv_pairs = sizeof(tv_2_ec_keys)/sizeof(const uint8_t *)
    },
    {0}
};

struct aws_cryptosdk_edk edk_init_from_test_vector(struct raw_aes_mk_test_vector * tv) {
    return build_test_edk_init(tv->edk_bytes, tv->edk_bytes_len, tv->iv);
}

struct aws_cryptosdk_edk edk_init_from_test_vector_idx(int idx) {
    return build_test_edk_init(raw_aes_mk_test_vectors[idx].edk_bytes,
                               raw_aes_mk_test_vectors[idx].edk_bytes_len,
                               raw_aes_mk_test_vectors[idx].iv);
}
