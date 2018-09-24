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
#include <aws/cryptosdk/private/materials.h>
#include <aws/cryptosdk/private/raw_rsa_keyring.h>
#include "raw_rsa_keyring_test_vectors.h"
#include "testing.h"

static struct aws_allocator *alloc;
static struct aws_cryptosdk_keyring *kr1;
static struct aws_cryptosdk_keyring *kr2;
static struct aws_cryptosdk_encryption_materials *enc_mat;
static struct aws_cryptosdk_decryption_materials *dec_mat;
static struct aws_cryptosdk_decryption_request req;

static enum aws_cryptosdk_alg_id alg_ids[] = { AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
                                               AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
                                               AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE };
                                            
static enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode[] = { AWS_CRYPTOSDK_RSA_PKCS1,
                                                                  AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1,
                                                                  AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1 };


static int copy_edks_from_enc_mat_to_dec_req() {
    TEST_ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk)));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_transfer_edk_list(&req.encrypted_data_keys, &enc_mat->encrypted_data_keys));

    return 0;
}

static int decrypt_data_key_and_verify_same_as_one_in_enc_mat() {
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_decrypt_data_key(kr2, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_INT_EQ(dec_mat->unencrypted_data_key.len, enc_mat->unencrypted_data_key.len);
    TEST_ASSERT(!memcmp(
        dec_mat->unencrypted_data_key.buffer, enc_mat->unencrypted_data_key.buffer, dec_mat->unencrypted_data_key.len));

    return 0;
}

static int set_up_encrypt_with_wrong_key(enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode, enum aws_cryptosdk_alg_id alg) {
    alloc = aws_default_allocator();
    kr1 = raw_rsa_keyring_tv_new_with_wrong_key(alloc, rsa_padding_mode);
    TEST_ASSERT_ADDR_NOT_NULL(kr1);
    enc_mat = aws_cryptosdk_encryption_materials_new(alloc, alg);
    TEST_ASSERT_ADDR_NOT_NULL(enc_mat);

    return 0;
}

static int set_up_encrypt_decrypt(enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode, enum aws_cryptosdk_alg_id alg) {
    alloc = aws_default_allocator();
    kr2 = raw_rsa_keyring_tv_new(alloc, rsa_padding_mode);
    TEST_ASSERT_ADDR_NOT_NULL(kr2);
    req.alloc = alloc;
    req.alg = alg;
    enc_mat = aws_cryptosdk_encryption_materials_new(alloc, alg);
    TEST_ASSERT_ADDR_NOT_NULL(enc_mat);
    dec_mat = aws_cryptosdk_decryption_materials_new(alloc, alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    return 0;
}

static void tear_down_encrypt() {
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_keyring_release(kr1);
}

static void tear_down_encrypt_decrypt() {
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_cryptosdk_edk_list_clean_up(&req.encrypted_data_keys);
    aws_cryptosdk_keyring_release(kr2);
}

/**
 * Testing generate and decrypt functions for all of the supported RSA padding modes.
 */
int generate_decrypt_from_data_key() {
    for (int wrap_idx = 0; wrap_idx < sizeof(rsa_padding_mode) / sizeof(*rsa_padding_mode); ++wrap_idx) {
        for (int alg_idx = 0; alg_idx < sizeof(alg_ids) / sizeof(enum aws_cryptosdk_alg_id); ++alg_idx) {
            TEST_ASSERT_SUCCESS(set_up_encrypt_decrypt(rsa_padding_mode[wrap_idx], alg_ids[alg_idx]));
            TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_generate_data_key(kr2, enc_mat));
            TEST_ASSERT_ADDR_NOT_NULL(enc_mat->unencrypted_data_key.buffer);

            const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_ids[alg_idx]);
            TEST_ASSERT_INT_EQ(enc_mat->unencrypted_data_key.len, props->data_key_len);
            TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);

            TEST_ASSERT_SUCCESS(copy_edks_from_enc_mat_to_dec_req());
            TEST_ASSERT_SUCCESS(decrypt_data_key_and_verify_same_as_one_in_enc_mat());
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
        TEST_ASSERT_SUCCESS(set_up_encrypt_decrypt(tv->rsa_padding_mode, tv->alg));
        // copy from constant memory because cleanup needs to zero it out
        memcpy(data_key_dup, tv->data_key, tv->data_key_len);
        enc_mat->unencrypted_data_key = aws_byte_buf_from_array(data_key_dup, tv->data_key_len);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_encrypt_data_key(kr2, enc_mat));
        TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);

        TEST_ASSERT_SUCCESS(copy_edks_from_enc_mat_to_dec_req());
        TEST_ASSERT_SUCCESS(decrypt_data_key_and_verify_same_as_one_in_enc_mat());
        tear_down_encrypt_decrypt();
    }
    return 0;
}

/**
 * Test to check for encryption failure of an unencrypted data key with an incorrect rsa private key.
 */
int encrypt_data_key_from_bad_rsa_private_key() {
    uint8_t data_key_dup[32];
    struct raw_rsa_keyring_test_vector tv = raw_rsa_keyring_test_vectors[0];
    TEST_ASSERT_SUCCESS(set_up_encrypt_with_wrong_key(tv.rsa_padding_mode, tv.alg));
    memcpy(data_key_dup, tv.data_key, tv.data_key_len);
    enc_mat->unencrypted_data_key = aws_byte_buf_from_array(data_key_dup, tv.data_key_len);
    TEST_ASSERT_SUCCESS(!aws_cryptosdk_keyring_encrypt_data_key(kr1, enc_mat));
    tear_down_encrypt();

    return 0;
}
struct test_case raw_rsa_keyring_encrypt_test_cases[] = {
    { "raw_rsa_keyring", "generate_decrypt_from_data_key", generate_decrypt_from_data_key },
    { "raw_rsa_keyring", "encrypt_decrypt_data_key_from_test_vectors", encrypt_decrypt_data_key_from_test_vectors },
    { "raw_rsa_keyring", "encrypt_data_key_from_bad_rsa_private_key", encrypt_data_key_from_bad_rsa_private_key },
    { NULL }
};
