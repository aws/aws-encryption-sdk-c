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
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/raw_rsa_keyring.h>
#include "raw_rsa_keyring_test_vectors.h"
#include "testing.h"

static struct aws_allocator *alloc;
//FIXME: refactor to use one keyring pointer and one setup/teardown function pair
static struct aws_cryptosdk_keyring *kr1;
static struct aws_cryptosdk_keyring *kr2;
static struct aws_array_list edks;
static struct aws_byte_buf unencrypted_data_key = {0};
// same key, after it has been encrypted and then decrypted
static struct aws_byte_buf decrypted_data_key = {0};

static enum aws_cryptosdk_alg_id alg_ids[] = { AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
                                               AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
                                               AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE };
                                            
static enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode[] = { AWS_CRYPTOSDK_RSA_PKCS1,
                                                                  AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1,
                                                                  AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1 };

static int set_up_encrypt_with_wrong_key(enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode) {
    alloc = aws_default_allocator();
    kr1 = raw_rsa_keyring_tv_new_with_wrong_key(alloc, rsa_padding_mode);
    TEST_ASSERT_ADDR_NOT_NULL(kr1);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &edks));

    return 0;
}

static void tear_down_encrypt() {
    aws_cryptosdk_keyring_release(kr1);
    aws_cryptosdk_edk_list_clean_up(&edks);
    aws_byte_buf_clean_up(&unencrypted_data_key);
}

static int set_up_encrypt_decrypt(enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode) {
    alloc = aws_default_allocator();
    kr2 = raw_rsa_keyring_tv_new(alloc, rsa_padding_mode);
    TEST_ASSERT_ADDR_NOT_NULL(kr2);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &edks));

    return 0;
}

static void tear_down_encrypt_decrypt() {
    aws_cryptosdk_keyring_release(kr2);
    aws_cryptosdk_edk_list_clean_up(&edks);
    aws_byte_buf_clean_up(&unencrypted_data_key);
    aws_byte_buf_clean_up(&decrypted_data_key);
}

/**
 * Testing generate and decrypt functions for all of the supported RSA padding modes.
 */
int generate_decrypt_from_data_key() {
    for (int wrap_idx = 0; wrap_idx < sizeof(rsa_padding_mode) / sizeof(*rsa_padding_mode); ++wrap_idx) {
        for (int alg_idx = 0; alg_idx < sizeof(alg_ids) / sizeof(enum aws_cryptosdk_alg_id); ++alg_idx) {
            TEST_ASSERT_SUCCESS(set_up_encrypt_decrypt(rsa_padding_mode[wrap_idx]));
            TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(kr2,
                                                                 alloc,
                                                                 &unencrypted_data_key,
                                                                 &edks,
                                                                 NULL,
                                                                 alg_ids[alg_idx]));
            TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);

            const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_ids[alg_idx]);
            TEST_ASSERT_INT_EQ(unencrypted_data_key.len, props->data_key_len);
            TEST_ASSERT_INT_EQ(aws_array_list_length(&edks), 1);

            TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(kr2,
                                                                 alloc,
                                                                 &decrypted_data_key,
                                                                 &edks,
                                                                 NULL,
                                                                 alg_ids[alg_idx]));
            TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &decrypted_data_key));
            tear_down_encrypt_decrypt();
        }
    }
    return 0;
}

/**
 * RSA Data key encryption and decryption with set of known test vectors.
 */
int encrypt_decrypt_data_key_from_test_vectors() {
    uint8_t data_key_dup[32];
    for (struct raw_rsa_keyring_test_vector *tv = raw_rsa_keyring_test_vectors; tv->data_key; ++tv) {
        TEST_ASSERT_SUCCESS(set_up_encrypt_decrypt(tv->rsa_padding_mode));
        // copy from constant memory because cleanup needs to zero it out
        memcpy(data_key_dup, tv->data_key, tv->data_key_len);
        unencrypted_data_key = aws_byte_buf_from_array(data_key_dup, tv->data_key_len);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(kr2,
                                                             alloc,
                                                             &unencrypted_data_key,
                                                             &edks,
                                                             NULL,
                                                             tv->alg));
        TEST_ASSERT_INT_EQ(aws_array_list_length(&edks), 1);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(kr2,
                                                             alloc,
                                                             &decrypted_data_key,
                                                             &edks,
                                                             NULL,
                                                             tv->alg));
        TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &decrypted_data_key));
        tear_down_encrypt_decrypt();
    }
    return 0;
}

/**
 * Test to check for encryption failure of an unencrypted data key with an incorrect rsa public key.
 */
int encrypt_data_key_from_bad_rsa_public_key() {
    uint8_t data_key_dup[32];
    struct raw_rsa_keyring_test_vector tv = raw_rsa_keyring_test_vectors[0];
    TEST_ASSERT_SUCCESS(set_up_encrypt_with_wrong_key(tv.rsa_padding_mode));
    memcpy(data_key_dup, tv.data_key, tv.data_key_len);
    unencrypted_data_key = aws_byte_buf_from_array(data_key_dup, tv.data_key_len);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(kr1,
                                                          alloc,
                                                          &unencrypted_data_key,
                                                          &edks,
                                                          NULL,
                                                          tv.alg) == AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    TEST_ASSERT_INT_EQ(aws_array_list_length(&edks), 0);
    tear_down_encrypt();

    return 0;
}
/**
 * Test to check for cases when either or both the private and public rsa pem files are NULL
 */
int test_for_null_pem_files_while_setting_up_rsa_kr()
{
    struct aws_cryptosdk_keyring *kr = NULL;
    alloc = aws_default_allocator();
    const uint8_t raw_rsa_keyring_tv_master_key_id[] = "master key ID";
    const uint8_t raw_rsa_keyring_tv_provider_id[] = "provider ID";
    const char raw_rsa_keyring_tv_public_key[] = "Test not-NULL public key";
    const char raw_rsa_keyring_tv_private_key[] = "Test not-NULL private key";

    kr = aws_cryptosdk_raw_rsa_keyring_new(alloc, raw_rsa_keyring_tv_master_key_id, strlen((const char *)raw_rsa_keyring_tv_master_key_id),
                                           raw_rsa_keyring_tv_provider_id, strlen((const char *)raw_rsa_keyring_tv_provider_id),
                                           NULL, NULL, AWS_CRYPTOSDK_RSA_PKCS1);
    TEST_ASSERT_ADDR_NULL(kr);

    kr = aws_cryptosdk_raw_rsa_keyring_new(alloc, raw_rsa_keyring_tv_master_key_id, strlen((const char *)raw_rsa_keyring_tv_master_key_id),
                                           raw_rsa_keyring_tv_provider_id, strlen((const char *)raw_rsa_keyring_tv_provider_id),
                                           raw_rsa_keyring_tv_private_key, NULL, AWS_CRYPTOSDK_RSA_PKCS1);
    TEST_ASSERT_ADDR_NOT_NULL(kr);
    aws_cryptosdk_keyring_release(kr);

    kr = aws_cryptosdk_raw_rsa_keyring_new(alloc, raw_rsa_keyring_tv_master_key_id, strlen((const char *)raw_rsa_keyring_tv_master_key_id),
                                           raw_rsa_keyring_tv_provider_id, strlen((const char *)raw_rsa_keyring_tv_provider_id),
                                           NULL, raw_rsa_keyring_tv_public_key, AWS_CRYPTOSDK_RSA_PKCS1);
    TEST_ASSERT_ADDR_NOT_NULL(kr);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}
struct test_case raw_rsa_keyring_encrypt_test_cases[] = {
    { "raw_rsa_keyring", "generate_decrypt_from_data_key", generate_decrypt_from_data_key },
    { "raw_rsa_keyring", "encrypt_decrypt_data_key_from_test_vectors", encrypt_decrypt_data_key_from_test_vectors },
    { "raw_rsa_keyring", "encrypt_data_key_from_bad_rsa_public_key", encrypt_data_key_from_bad_rsa_public_key },
    { "raw_rsa_keyring", "test_for_null_pem_files_while_setting_up_rsa_kr", test_for_null_pem_files_while_setting_up_rsa_kr },
    { NULL }
};
