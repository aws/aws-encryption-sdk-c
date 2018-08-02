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
#include <aws/cryptosdk/private/raw_aes_mk.h>
#include <aws/cryptosdk/private/materials.h>
#include "testing.h"

static const uint8_t test_vector_master_key_id[] = "asdfhasiufhiasuhviawurhgiuawrhefiuawhf";
static const uint8_t test_vector_provider_id[] = "static-random";
static const uint8_t test_vector_wrapping_key[] =
{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static struct aws_allocator * alloc;
static struct aws_cryptosdk_mk * mk;
static struct aws_hash_table enc_context;
static struct aws_cryptosdk_encryption_materials * enc_mat;
static struct aws_cryptosdk_decryption_request req;
static struct aws_cryptosdk_decryption_materials * dec_mat;

static int put_stuff_in_encryption_context() {
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_1, "aaaaaaaa\xc2\x80");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_1, "AAAAAAAA");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_2, "aaaaaaaa\x7f");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_2, "BBBBBBBB");
    struct aws_hash_element * elem;
    TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_context, (void *)enc_context_key_1, &elem, NULL));
    elem->value = (void *)enc_context_val_1;
    TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_context, (void *)enc_context_key_2, &elem, NULL));
    elem->value = (void *)enc_context_val_2;

    return 0;
}

static int set_up_encrypt(enum aws_cryptosdk_aes_key_len raw_key_len,
                          enum aws_cryptosdk_alg_id alg,
                          bool fill_enc_context) {
    alloc = aws_default_allocator();

    mk = aws_cryptosdk_raw_aes_mk_new(alloc,
                                      test_vector_master_key_id,
                                      sizeof(test_vector_master_key_id) - 1,
                                      test_vector_provider_id,
                                      sizeof(test_vector_provider_id) - 1,
                                      test_vector_wrapping_key,
                                      raw_key_len);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    TEST_ASSERT_SUCCESS(aws_hash_table_init(&enc_context, alloc, 5, aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy));

    if (fill_enc_context) TEST_ASSERT_SUCCESS(put_stuff_in_encryption_context());

    enc_mat = aws_cryptosdk_encryption_materials_new(alloc, alg, 1);
    TEST_ASSERT_ADDR_NOT_NULL(enc_mat);
    enc_mat->enc_context = &enc_context;

    return 0;
}

static int set_up_encrypt_decrypt(enum aws_cryptosdk_aes_key_len raw_key_len,
                                  enum aws_cryptosdk_alg_id alg,
                                  bool fill_enc_context) {
    TEST_ASSERT_SUCCESS(set_up_encrypt(raw_key_len, alg, fill_enc_context));

    dec_mat = aws_cryptosdk_decryption_materials_new(alloc, alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    req.enc_context = &enc_context;
    req.alloc = alloc;
    req.alg = alg;

    return 0;
}

static void tear_down_encrypt() {
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_hash_table_clean_up(&enc_context);
    aws_cryptosdk_mk_destroy(mk);
}

static void tear_down_encrypt_decrypt() {
    tear_down_encrypt();
    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    // cleans up list only, not the allocated memory in the EDKs, but they were a copy of the pointers in enc_mat which are already being freed.
    aws_array_list_clean_up(&req.encrypted_data_keys);
}

static int copy_edks_from_enc_mat_to_dec_req() {
    TEST_ASSERT_SUCCESS(aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk)));
    TEST_ASSERT_SUCCESS(aws_array_list_copy(&enc_mat->encrypted_data_keys, &req.encrypted_data_keys));

    return 0;
}

static int decrypt_data_key_and_verify_same_as_one_in_enc_mat() {
    TEST_ASSERT_SUCCESS(aws_cryptosdk_mk_decrypt_data_key(mk, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_INT_EQ(dec_mat->unencrypted_data_key.len, enc_mat->unencrypted_data_key.len);
    TEST_ASSERT(!memcmp(dec_mat->unencrypted_data_key.buffer, enc_mat->unencrypted_data_key.buffer, dec_mat->unencrypted_data_key.len));

    return 0;
}

enum aws_cryptosdk_aes_key_len raw_key_lens[] = {AWS_CRYPTOSDK_AES_128, AWS_CRYPTOSDK_AES_192, AWS_CRYPTOSDK_AES_256};
enum aws_cryptosdk_alg_id algs[] = {AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
                                    AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
                                    AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE};

int encrypt_decrypt_data_key() {
    for (int fill_enc_context = 0; fill_enc_context < 2; ++fill_enc_context) {
        for (int key_len_idx = 0; key_len_idx < sizeof(raw_key_lens)/sizeof(enum aws_cryptosdk_aes_key_len); ++key_len_idx) {
            for (int alg_idx = 0; alg_idx < sizeof(algs)/sizeof(enum aws_cryptosdk_alg_id); ++alg_idx) {
                TEST_ASSERT_SUCCESS(set_up_encrypt_decrypt(raw_key_lens[key_len_idx], algs[alg_idx], fill_enc_context));

                const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(algs[alg_idx]);
                TEST_ASSERT_SUCCESS(aws_byte_buf_init(alloc, &enc_mat->unencrypted_data_key, props->data_key_len));
                memset(enc_mat->unencrypted_data_key.buffer, 0x77, props->data_key_len);
                enc_mat->unencrypted_data_key.len = enc_mat->unencrypted_data_key.capacity;

                TEST_ASSERT_SUCCESS(aws_cryptosdk_mk_encrypt_data_key(mk, enc_mat));
                TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);
    
                TEST_ASSERT_SUCCESS(copy_edks_from_enc_mat_to_dec_req());

                TEST_ASSERT_SUCCESS(decrypt_data_key_and_verify_same_as_one_in_enc_mat());

                tear_down_encrypt_decrypt();
            }
        }
    }
    return 0;
}

int generate_decrypt_data_key() {
    for (int fill_enc_context = 0; fill_enc_context < 2; ++fill_enc_context) {
        for (int key_len_idx = 0; key_len_idx < sizeof(raw_key_lens)/sizeof(enum aws_cryptosdk_aes_key_len); ++key_len_idx) {
            for (int alg_idx = 0; alg_idx < sizeof(algs)/sizeof(enum aws_cryptosdk_alg_id); ++alg_idx) {
                TEST_ASSERT_SUCCESS(set_up_encrypt_decrypt(raw_key_lens[key_len_idx], algs[alg_idx], fill_enc_context));

                TEST_ASSERT_SUCCESS(aws_cryptosdk_mk_generate_data_key(mk, enc_mat));
                TEST_ASSERT_ADDR_NOT_NULL(enc_mat->unencrypted_data_key.buffer);

                const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(algs[alg_idx]);
                TEST_ASSERT_INT_EQ(enc_mat->unencrypted_data_key.len, props->data_key_len);
                TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);

                TEST_ASSERT_SUCCESS(copy_edks_from_enc_mat_to_dec_req());

                TEST_ASSERT_SUCCESS(decrypt_data_key_and_verify_same_as_one_in_enc_mat());

                tear_down_encrypt_decrypt();
            }
        }
    }
    return 0;
}

/**
 * The same test vector as decrypt_data_key_empty_enc_context in the encrypt direction.
 */
int encrypt_data_key_empty_enc_context() {
    static const uint8_t iv[] = {0xbe, 0xa0, 0xfb, 0xd0, 0x0e, 0xee, 0x0d, 0x94, 0xd9, 0xb1, 0xb3, 0x93};
    uint8_t data_key[] = // not const because cleanup needs to zero it out
        {0xdd, 0xc2, 0xf6, 0x5f, 0x96, 0xa2, 0xda, 0x96, 0x86, 0xea, 0xd6, 0x58, 0xfe, 0xe9, 0xc0, 0xc3,
         0xb6, 0xd4, 0xb1, 0x92, 0xf2, 0xba, 0x50, 0x93, 0x21, 0x97, 0x62, 0xab, 0x7d, 0x25, 0x9f, 0x2c};

    TEST_ASSERT_SUCCESS(set_up_encrypt(AWS_CRYPTOSDK_AES_256, AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE, false));
    enc_mat->unencrypted_data_key = aws_byte_buf_from_array(data_key, sizeof(data_key));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_raw_aes_mk_encrypt_data_key_with_iv(mk, enc_mat, iv));
    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);

    struct aws_cryptosdk_edk edk;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&enc_mat->encrypted_data_keys, (void *)&edk, 0));

    TEST_ASSERT_BUF_EQ(edk.enc_data_key,
                       0x54, 0x2b, 0xf0, 0xdc, 0x35, 0x20, 0x07, 0x38, 0xe4, 0x9e, 0x34, 0xfa, 0xa6, 0xbf, 0x11, 0xed,
                       0x45, 0x40, 0x97, 0xfd, 0xb8, 0xe3, 0x36, 0x75, 0x5c, 0x03, 0xbb, 0x9f, 0xa4, 0x42, 0x9e, 0x66,
                       0x44, 0x7c, 0x39, 0xf7, 0x7f, 0xfe, 0xbc, 0xa5, 0x98, 0x70, 0xe9, 0xa8, 0xc9, 0xb5, 0x7f, 0x6f);

    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV

    TEST_ASSERT(!memcmp(edk.provider_info.buffer, edk_provider_info, edk.provider_info.len));
    TEST_ASSERT(!memcmp(edk.provider_id.buffer, test_vector_provider_id, edk.provider_id.len));

    tear_down_encrypt();
    return 0;
}

/**
 * The same test vector as decrypt_data_key_unsigned_comparison_192 in the encrypt direction.
 */
int encrypt_data_key_unsigned_comparison_192() {
    static const uint8_t iv[] = {0x75, 0x21, 0x9f, 0x96, 0x77, 0xaa, 0xc8, 0x9e, 0xd8, 0x53, 0x8f, 0x57};
    uint8_t data_key[] = // not const because cleanup needs to zero it out
        {0xfa, 0xce, 0xa0, 0x72, 0x10, 0x80, 0x80, 0x7a, 0x9d, 0xdb, 0x1f, 0x9a, 0x8d, 0x68, 0xee, 0xb0,
         0x86, 0xb5, 0x45, 0xcc, 0x4d, 0x8d, 0xc5, 0x75, 0x7a, 0x36, 0xc1, 0xd2, 0x78, 0x8b, 0x01, 0x1f};

    TEST_ASSERT_SUCCESS(set_up_encrypt(AWS_CRYPTOSDK_AES_192, AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE, true));
    enc_mat->unencrypted_data_key = aws_byte_buf_from_array(data_key, sizeof(data_key));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_raw_aes_mk_encrypt_data_key_with_iv(mk, enc_mat, iv));
    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);

    struct aws_cryptosdk_edk edk;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&enc_mat->encrypted_data_keys, (void *)&edk, 0));

    TEST_ASSERT_BUF_EQ(edk.enc_data_key,
                       0x70, 0x73, 0x47, 0x19, 0x91, 0x77, 0x3b, 0xac, 0x64, 0x4a, 0x20, 0x0a, 0x81, 0x56, 0x8c, 0x5c,
                       0x69, 0xe4, 0x62, 0x28, 0xbc, 0x6c, 0x6c, 0x6b, 0xd6, 0x3a, 0x3c, 0xfb, 0xf0, 0x80, 0xc7, 0xf1,
                       0xb8, 0xee, 0xc8, 0xa1, 0x5c, 0x6c, 0xc2, 0x81, 0x3a, 0xcc, 0xd2, 0xdb, 0x52, 0x77, 0x55, 0x49);

    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\x75\x21\x9f\x96\x77\xaa\xc8\x9e\xd8\x53\x8f\x57"; // IV

    TEST_ASSERT(!memcmp(edk.provider_info.buffer, edk_provider_info, edk.provider_info.len));
    TEST_ASSERT(!memcmp(edk.provider_id.buffer, test_vector_provider_id, edk.provider_id.len));

    tear_down_encrypt();
    return 0;
}

/**
 * The same test vector as decrypt_data_key_128_valid in the encrypt direction.
 */
int encrypt_data_key_128() {
    static const uint8_t iv[] = {0x8e, 0x2b, 0xfd, 0x25, 0x66, 0x5a, 0x1c, 0x0d, 0x0d, 0x4a, 0x49, 0x14};
    uint8_t data_key[] = // not const because cleanup needs to zero it out
        {0x6d, 0x3f, 0xf7, 0xe9, 0x0e, 0xe4, 0x81, 0x09, 0x87, 0x8f, 0x37, 0xd9, 0x6a, 0x21, 0xe5, 0xf8};

    TEST_ASSERT_SUCCESS(set_up_encrypt(AWS_CRYPTOSDK_AES_128, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE, false));
    enc_mat->unencrypted_data_key = aws_byte_buf_from_array(data_key, sizeof(data_key));

    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key, "correct");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val, "context");

    struct aws_hash_element * elem;
    TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_context, (void *)enc_context_key, &elem, NULL));
    elem->value = (void *)enc_context_val;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_raw_aes_mk_encrypt_data_key_with_iv(mk, enc_mat, iv));
    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);

    struct aws_cryptosdk_edk edk;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&enc_mat->encrypted_data_keys, (void *)&edk, 0));

    TEST_ASSERT_BUF_EQ(edk.enc_data_key,
                       0x29, 0x09, 0x38, 0x89, 0xe4, 0x4e, 0x1c, 0xdc, 0xf0, 0x4d, 0x0b, 0xa1, 0xe4, 0x52, 0xd5, 0x77,
                       0x53, 0xf8, 0x23, 0x7a, 0x52, 0xd9, 0xca, 0xa8, 0x53, 0x6e, 0xf9, 0xcb, 0xae, 0x22, 0x63, 0xae);

    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\x8e\x2b\xfd\x25\x66\x5a\x1c\x0d\x0d\x4a\x49\x14"; // IV

    TEST_ASSERT(!memcmp(edk.provider_info.buffer, edk_provider_info, edk.provider_info.len));
    TEST_ASSERT(!memcmp(edk.provider_id.buffer, test_vector_provider_id, edk.provider_id.len));

    tear_down_encrypt();
    return 0;
}

struct test_case raw_aes_mk_encrypt_test_cases[] = {
    { "raw_aes_mk", "encrypt_decrypt_data_key", encrypt_decrypt_data_key },
    { "raw_aes_mk", "generate_decrypt_data_key", generate_decrypt_data_key },
    { "raw_aes_mk", "encrypt_data_key_empty_enc_context", encrypt_data_key_empty_enc_context },
    { "raw_aes_mk", "encrypt_data_key_unsigned_comparison_192", encrypt_data_key_unsigned_comparison_192 },
    { "raw_aes_mk", "encrypt_data_key_128", encrypt_data_key_128 },
    { NULL }
};
