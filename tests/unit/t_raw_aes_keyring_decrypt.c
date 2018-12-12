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
#include <stdlib.h>
#include <aws/cryptosdk/private/raw_aes_keyring.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/materials.h>
#include "raw_aes_keyring_test_vectors.h"
#include "testing.h"

static struct aws_cryptosdk_edk good_edk() {
    return edk_init_from_test_vector_idx(0);
}

/**
 * A bunch of wrong EDKs for testing various failure scenarios.
 */
static struct aws_cryptosdk_edk empty_edk() {
    struct aws_cryptosdk_edk edk = {{0}};
    return edk;
}

static struct aws_cryptosdk_edk wrong_provider_id_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.provider_id = aws_byte_buf_from_c_str("foobar");
    return edk;
} 

static struct aws_cryptosdk_edk wrong_edk_bytes_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.enc_data_key.len--;
    return edk;
}

static struct aws_cryptosdk_edk wrong_provider_info_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.provider_info.len--;
    return edk;
}

static struct aws_cryptosdk_edk wrong_master_key_id_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuOOPS" // wrong master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV
    aws_byte_buf_clean_up(&edk.provider_info);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

static struct aws_cryptosdk_edk wrong_iv_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0d" // wrong IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV
    aws_byte_buf_clean_up(&edk.provider_info);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

static struct aws_cryptosdk_edk wrong_tag_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x81" // wrong GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV
    aws_byte_buf_clean_up(&edk.provider_info);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

static struct aws_cryptosdk_edk wrong_edk_bytes() {
    struct aws_cryptosdk_edk edk = good_edk();
    static const uint8_t edk_bytes[] =
    {0xDE, 0xAD, 0xBE, 0xEF, 0x35, 0x20, 0x07, 0x38, 0xe4, 0x9e, 0x34, 0xfa, 0xa6, 0xbf, 0x11, 0xed,
     0x45, 0x40, 0x97, 0xfd, 0xb8, 0xe3, 0x36, 0x75, 0x5c, 0x03, 0xbb, 0x9f, 0xa4, 0x42, 0x9e, 0x66,
     0x44, 0x7c, 0x39, 0xf7, 0x7f, 0xfe, 0xbc, 0xa5, 0x98, 0x70, 0xe9, 0xa8, 0xc9, 0xb5, 0x7f, 0x6f};
    edk.enc_data_key = aws_byte_buf_from_array(edk_bytes, sizeof(edk_bytes));
    return edk;
}

static struct aws_cryptosdk_edk wrong_iv_bytes() {
    // first 32 bytes: encrypted data key, last 16 bytes GCM tag
    static const uint8_t edk_bytes[] =
        {0x54, 0x2b, 0xf0, 0xdc, 0x35, 0x20, 0x07, 0x38, 0xe4, 0x9e, 0x34, 0xfa, 0xa6, 0xbf, 0x11, 0xed,
         0x45, 0x40, 0x97, 0xfd, 0xb8, 0xe3, 0x36, 0x75, 0x5c, 0x03, 0xbb, 0x9f, 0xa4, 0x42, 0x9e, 0x66,
         0x44, 0x7c, 0x39, 0xf7, 0x7f, 0xfe, 0xbc, 0xa5, 0x98, 0x70, 0xe9, 0xa8, 0xc9, 0xb5, 0x7f, 0x6f};

    static const uint8_t iv[RAW_AES_KR_IV_LEN] = {0};

    return build_test_edk_init(edk_bytes, sizeof(edk_bytes), iv);
}

static struct aws_allocator * alloc;
static struct aws_cryptosdk_keyring * kr;
static struct aws_hash_table enc_context;
static struct aws_array_list keyring_trace;
static struct aws_array_list edks;
static struct aws_byte_buf unencrypted_data_key = {0};

static int set_up_all_the_things(const struct aws_string ** keys,
                                 const struct aws_string ** vals,
                                 size_t num_kv_pairs,
                                 enum aws_cryptosdk_aes_key_len raw_key_len) {
    alloc = aws_default_allocator();
    kr = raw_aes_keyring_tv_new(alloc, raw_key_len);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(alloc, &enc_context));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &keyring_trace));

    for (size_t key_idx = 0; key_idx < num_kv_pairs; ++key_idx) {
        struct aws_hash_element * elem;
        TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_context, (void *)keys[key_idx], &elem, NULL));
        elem->value = (void *)vals[key_idx];
    }
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &edks));

    return 0;
}

static void tear_down_all_the_things() {
    aws_cryptosdk_edk_list_clean_up(&edks);
    aws_cryptosdk_enc_context_clean_up(&enc_context);
    aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
    aws_cryptosdk_keyring_release(kr);
    aws_byte_buf_clean_up(&unencrypted_data_key);
}

/**
 * Data key decryption with set of known test vectors. This set includes wrapping keys of
 * 256, 192, and 128 bits. Same vectors as used in decrypt_data_key_test_vectors.
 *
 * Also verifies that decryption does not work when encryption context is altered.
 */
int decrypt_data_key_test_vectors() {
    for (int corrupt_enc_context = 0; corrupt_enc_context < 2; ++corrupt_enc_context) {
        for (struct raw_aes_keyring_test_vector * tv = raw_aes_keyring_test_vectors; tv->data_key; ++tv) {
            TEST_ASSERT_SUCCESS(set_up_all_the_things(NULL, NULL, 0, tv->raw_key_len));
            TEST_ASSERT_SUCCESS(set_test_vector_encryption_context(alloc, &enc_context, tv));

            if (corrupt_enc_context) {
                AWS_STATIC_STRING_FROM_LITERAL(key, "RFC 3514");
                AWS_STATIC_STRING_FROM_LITERAL(val, "setting the evil bit to 1");
                struct aws_hash_element * elem;
                TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_context, (void *)key, &elem, NULL));
                elem->value = (void *)val;
            }

            struct aws_cryptosdk_edk edk = edk_init_from_test_vector(tv);
            aws_array_list_push_back(&edks, (void *)&edk);

            TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(kr,
                                                                 alloc,
                                                                 &unencrypted_data_key,
                                                                 &keyring_trace,
                                                                 &edks,
                                                                 &enc_context,
                                                                 tv->alg));

            if (corrupt_enc_context) {
                TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);
            } else {
                TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);

                struct aws_byte_buf known_answer = aws_byte_buf_from_array(tv->data_key,
                                                                           tv->data_key_len);
                TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &known_answer));
                TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                                        &keyring_trace,
                                        AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX |
                                        AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));
            }

            tear_down_all_the_things();
        }
    }
    return 0;
}

typedef struct aws_cryptosdk_edk (*edk_generator)();

edk_generator edk_gens[] = {empty_edk,
                            wrong_provider_id_edk,
                            wrong_edk_bytes_len_edk,
                            wrong_provider_info_len_edk,
                            wrong_master_key_id_edk,
                            wrong_iv_len_edk,
                            wrong_tag_len_edk,
                            wrong_edk_bytes,
                            wrong_iv_bytes,
                            good_edk};

/**
 * Same as the first test vector but EDK list has many wrong EDKs which fail for different reasons before
 * getting to good one.
 */
int decrypt_data_key_multiple_edks() {
    struct raw_aes_keyring_test_vector tv = raw_aes_keyring_test_vectors[0];
    TEST_ASSERT_SUCCESS(set_up_all_the_things(NULL, NULL, 0, tv.raw_key_len));

    for (int idx = 0; idx < sizeof(edk_gens)/sizeof(edk_generator); ++idx) {
        struct aws_cryptosdk_edk edk = edk_gens[idx]();
        aws_array_list_push_back(&edks, (void *)&edk);
    }

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_keyring_on_decrypt(kr,
                                                                        alloc,
                                                                        &unencrypted_data_key,
                                                                        &keyring_trace,
                                                                        &edks,
                                                                        &enc_context,
                                                                        tv.alg));
    TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);

    struct aws_byte_buf known_answer = aws_byte_buf_from_array(tv.data_key, tv.data_key_len);
    TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &known_answer));
    TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                    &keyring_trace,
                    AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX |
                    AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));

    tear_down_all_the_things();
    return 0;
}

/**
 * Same as the last test but omits the final (good) EDK from the list, so decryption fails.
 */
int decrypt_data_key_no_good_edk() {
    struct raw_aes_keyring_test_vector tv = raw_aes_keyring_test_vectors[0];
    TEST_ASSERT_SUCCESS(set_up_all_the_things(NULL, NULL, 0, tv.raw_key_len));

    for (int idx = 0; idx < sizeof(edk_gens)/sizeof(edk_generator) - 1; ++idx) {
        struct aws_cryptosdk_edk edk = edk_gens[idx]();
        aws_array_list_push_back(&edks, (void *)&edk);
    }

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_keyring_on_decrypt(kr,
                                                                        alloc,
                                                                        &unencrypted_data_key,
                                                                        &keyring_trace,
                                                                        &edks,
                                                                        &enc_context,
                                                                        tv.alg));
    TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);
    TEST_ASSERT(!aws_array_list_length(&keyring_trace));

    tear_down_all_the_things();
    return 0;
}

/**
 * Single EDK test with algorithm suite including signing, so that there is an encryption context with
 * public key.
 */
int decrypt_data_key_with_sig() {
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key, "aws-crypto-public-key");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val,
                                   "AguATtjJFzJnlpNXdyDG7e8bfLZYRx+vxdAmYz+ztVBYyFhsMpchjz9ev3MdXQMD9Q==");

    TEST_ASSERT_SUCCESS(set_up_all_the_things(&enc_context_key, &enc_context_val, 1, AWS_CRYPTOSDK_AES_256));

    // first 32 bytes encrypted data key, last 16 bytes GCM tag
    const uint8_t edk_bytes[] =
        {0xff, 0xaf, 0xb4, 0x82, 0xf0, 0x0f, 0x9b, 0x4e, 0x5e, 0x0e, 0x75, 0xea, 0x67, 0xbb, 0x80, 0xc6,
         0x5a, 0x37, 0x18, 0x35, 0x55, 0x62, 0xfb, 0x9c, 0x9e, 0x90, 0xd8, 0xae, 0xdd, 0x39, 0xd0, 0x67,
         0x85, 0x0e, 0x18, 0x5b, 0xcb, 0x92, 0xc7, 0xbb, 0xff, 0x88, 0xfd, 0xe8, 0xf9, 0x33, 0x6c, 0x74};

    const uint8_t iv[] = {0x1b, 0x48, 0x76, 0xb4, 0x7a, 0x10, 0x16, 0x19, 0xeb, 0x3f, 0x93, 0x1d};

    struct aws_cryptosdk_edk edk = build_test_edk_init(edk_bytes, sizeof(edk_bytes), iv);
    aws_array_list_push_back(&edks, (void *)&edk);
    
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(kr,
                                                         alloc,
                                                         &unencrypted_data_key,
                                                         &keyring_trace,
                                                         &edks,
                                                         &enc_context,
                                                         AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384));

    TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);
    TEST_ASSERT_BUF_EQ(
        unencrypted_data_key,
        0x9b, 0x01, 0xc1, 0xaa, 0x62, 0x25, 0x1d, 0x0f, 0x16, 0xa0, 0xa2, 0x15, 0xea, 0xe4, 0xc2, 0x37,
        0x4a, 0x8c, 0xc7, 0x9f, 0xfa, 0x3a, 0xe7, 0xa2, 0xa4, 0xa8, 0x1e, 0x83, 0xba, 0x38, 0x23, 0x16);

    TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                    &keyring_trace,
                    AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX |
                    AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));
    tear_down_all_the_things();
    return 0;
}

/**
 * Same as the last test but with more stuff in the encryption context to verify that sorting and
 * serialization of encryption context works properly vis a vis decrypting data keys.
 */
int decrypt_data_key_with_sig_and_enc_context() {
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_1, "aws-crypto-public-key");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_1,
                                   "A/f8U0IfPC5vseQ13rHlkbPjK6c0jikfvY7F+I2PZxVI9ZHW38lbxMUabbPZdIgMOg==");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_2, "aaaaaaaa");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_2, "AAAAAAAA");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_3, "bbbbbbbb");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_3, "BBBBBBBB");

    const struct aws_string * keys[] = {enc_context_key_1, enc_context_key_2, enc_context_key_3};
    const struct aws_string * vals[] = {enc_context_val_1, enc_context_val_2, enc_context_val_3};

    TEST_ASSERT_SUCCESS(set_up_all_the_things(keys, vals, sizeof(keys)/sizeof(const struct aws_string *),
                                              AWS_CRYPTOSDK_AES_256));

    // first 32 bytes encrypted data key, last 16 bytes GCM tag
    const uint8_t edk_bytes[] =
        {0x14, 0xcc, 0xfb, 0xfe, 0x81, 0x50, 0x1e, 0x07, 0xe6, 0xc8, 0x34, 0x00, 0x95, 0xb1, 0x17, 0xd3,
         0x0e, 0x7c, 0xb9, 0x15, 0xc7, 0x45, 0x94, 0x0d, 0x34, 0xf7, 0xde, 0x11, 0x1b, 0x33, 0x5c, 0xbb,
         0xc7, 0x40, 0xc5, 0x23, 0xec, 0x5c, 0x3e, 0xc1, 0xa0, 0x54, 0x7a, 0x60, 0xab, 0x20, 0x85, 0xff};

    const uint8_t iv[] = {0x53, 0xd3, 0x06, 0x47, 0xee, 0xa2, 0x4d, 0x3e, 0xcd, 0x28, 0x16, 0x82};

    struct aws_cryptosdk_edk edk = build_test_edk_init(edk_bytes, sizeof(edk_bytes), iv);
    aws_array_list_push_back(&edks, (void *)&edk);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(kr,
                                                         alloc,
                                                         &unencrypted_data_key,
                                                         &keyring_trace,
                                                         &edks,
                                                         &enc_context,
                                                         AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384));

    TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);
    TEST_ASSERT_BUF_EQ(
        unencrypted_data_key,
        0xaf, 0x4e, 0xaa, 0x6f, 0x3e, 0x34, 0xfa, 0x50, 0x48, 0xd1, 0x48, 0x02, 0x33, 0x86, 0xc5, 0x98,
        0x2c, 0x64, 0xe3, 0x54, 0xc4, 0x27, 0xe3, 0x66, 0x39, 0x28, 0x94, 0x89, 0xf5, 0x71, 0x68, 0xcd);

    TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                    &keyring_trace,
                    AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX |
                    AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));

    tear_down_all_the_things();
    return 0;
}

struct test_case raw_aes_keyring_decrypt_test_cases[] = {
    { "raw_aes_keyring", "decrypt_data_key_test_vectors", decrypt_data_key_test_vectors },
    { "raw_aes_keyring", "decrypt_data_key_multiple_edks", decrypt_data_key_multiple_edks },
    { "raw_aes_keyring", "decrypt_data_key_no_good_edk", decrypt_data_key_no_good_edk },
    { "raw_aes_keyring", "decrypt_data_key_with_sig", decrypt_data_key_with_sig },
    { "raw_aes_keyring", "decrypt_data_key_with_sig_and_enc_context",
      decrypt_data_key_with_sig_and_enc_context },
    { NULL }
};
