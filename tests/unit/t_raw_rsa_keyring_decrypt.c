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

static struct aws_cryptosdk_edk good_edk() {
    return edk_init_test_vector_idx(0);
}
/**
 * A bunch of wrong EDKs for testing various failure scenarios.
 */
static struct aws_cryptosdk_edk empty_edk() {
    struct aws_cryptosdk_edk edk = { { 0 } };
    return edk;
}
static struct aws_cryptosdk_edk wrong_provider_id_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.provider_id              = aws_byte_buf_from_c_str("HelloWorld");
    return edk;
}
static struct aws_cryptosdk_edk wrong_edk_bytes_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.ciphertext.len--;
    return edk;
}

static struct aws_cryptosdk_edk wrong_edk_bytes() {
    struct aws_cryptosdk_edk edk     = good_edk();
    static const uint8_t edk_bytes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                         0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    edk.ciphertext                   = aws_byte_buf_from_array(edk_bytes, sizeof(edk_bytes));
    return edk;
}

static struct aws_cryptosdk_edk wrong_provider_info_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.provider_info.len--;
    return edk;
}
static struct aws_cryptosdk_edk wrong_master_key_id_edk() {
    struct aws_cryptosdk_edk edk             = good_edk();
    static const uint8_t edk_provider_info[] = "asdfhasiufhiasuhviawurhgiuawrhefiuOOPS";  // wrong master key ID
    aws_byte_buf_clean_up(&edk.provider_info);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

static struct aws_cryptosdk_edk enc_data_key_too_small_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.ciphertext.len           = 0;
    return edk;
}
static struct aws_cryptosdk_edk enc_data_key_too_large_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.ciphertext.len *= 2;
    return edk;
}

typedef struct aws_cryptosdk_edk (*edk_generator)();

edk_generator rsa_edk_gens[] = { empty_edk,
                                 wrong_provider_id_edk,
                                 wrong_edk_bytes_len_edk,
                                 wrong_edk_bytes,
                                 wrong_provider_info_len_edk,
                                 wrong_master_key_id_edk,
                                 enc_data_key_too_small_edk,
                                 enc_data_key_too_large_edk,
                                 good_edk };
static struct aws_allocator *alloc;
static struct aws_cryptosdk_keyring *kr;
static struct aws_array_list keyring_trace;
static struct aws_array_list edks;
static struct aws_byte_buf unencrypted_data_key = { 0 };

static int set_up_all_the_things(enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode, bool use_correct_private_key) {
    alloc = aws_default_allocator();
    kr    = (use_correct_private_key ? raw_rsa_keyring_tv_new : raw_rsa_keyring_tv_new_with_wrong_key)(
        alloc, rsa_padding_mode);
    TEST_ASSERT_ADDR_NOT_NULL(kr);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &edks));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &keyring_trace));
    return 0;
}

static void tear_down_all_the_things() {
    // We need to make sure our edk list is structually valid before calling cleanup
    for (size_t idx = 0; idx < aws_array_list_length(&edks); ++idx) {
        struct aws_cryptosdk_edk *edk = NULL;
        aws_array_list_get_at_ptr(&edks, (void **)&edk, idx);
        if (edk->ciphertext.len > edk->ciphertext.capacity) {
            edk->ciphertext.len = edk->ciphertext.capacity;
        }
    }

    aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
    aws_cryptosdk_edk_list_clean_up(&edks);
    aws_cryptosdk_keyring_release(kr);
    aws_byte_buf_clean_up(&unencrypted_data_key);
}

/**
 * RSA Data key decryption with set of known test vectors.
 */
int decrypt_data_key_from_test_vectors() {
    for (struct raw_rsa_keyring_test_vector *tv = raw_rsa_keyring_test_vectors; tv->data_key; ++tv) {
        TEST_ASSERT_SUCCESS(set_up_all_the_things(tv->rsa_padding_mode, true));

        struct aws_cryptosdk_edk edk = edk_init_test_vector(tv);
        aws_array_list_push_back(&edks, (void *)&edk);

        TEST_ASSERT_SUCCESS(
            aws_cryptosdk_keyring_on_decrypt(kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, tv->alg));
        TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);

        struct aws_byte_buf known_answer = aws_byte_buf_from_array(tv->data_key, tv->data_key_len);
        TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &known_answer));
        TEST_ASSERT_SUCCESS(
            raw_rsa_keyring_tv_trace_updated_properly(&keyring_trace, AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));
        tear_down_all_the_things();
    }
    return 0;
}
/**
 * Same as the first test vector but EDK list has many wrong EDKs which fail for different reasons before
 * getting to good one.
 */
int decrypt_data_key_from_multiple_edks() {
    struct raw_rsa_keyring_test_vector tv = raw_rsa_keyring_test_vectors[0];
    TEST_ASSERT_SUCCESS(set_up_all_the_things(tv.rsa_padding_mode, true));

    for (int idx = 0; idx < sizeof(rsa_edk_gens) / sizeof(edk_generator); ++idx) {
        struct aws_cryptosdk_edk edk = rsa_edk_gens[idx]();
        aws_array_list_push_back(&edks, (void *)&edk);
    }

    int result =
        aws_cryptosdk_keyring_on_decrypt(kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, tv.alg);
    // openssl 3 fails for bad keys
    if (result == AWS_OP_SUCCESS) {
        TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);

        struct aws_byte_buf known_answer = aws_byte_buf_from_array(tv.data_key, tv.data_key_len);
        TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &known_answer));
        TEST_ASSERT_SUCCESS(
            raw_rsa_keyring_tv_trace_updated_properly(&keyring_trace, AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));
    }
    tear_down_all_the_things();
    return 0;
}

/**
 * Same as the last test but omits the final (good) EDK from the list, so decryption fails.
 */
int decrypt_data_key_from_bad_edk() {
    struct raw_rsa_keyring_test_vector tv = raw_rsa_keyring_test_vectors[0];
    TEST_ASSERT_SUCCESS(set_up_all_the_things(tv.rsa_padding_mode, true));

    for (int idx = 0; idx < sizeof(rsa_edk_gens) / sizeof(edk_generator) - 1; ++idx) {
        struct aws_cryptosdk_edk edk = rsa_edk_gens[idx]();
        aws_array_list_push_back(&edks, (void *)&edk);
    }

    int result =
        aws_cryptosdk_keyring_on_decrypt(kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, tv.alg);
    // openssl 3 fails for bad keys
    if (result == AWS_OP_SUCCESS) {
        TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);
        TEST_ASSERT(!aws_array_list_length(&keyring_trace));
    }
    tear_down_all_the_things();
    return 0;
}

/**
 * Test to check for decryption failure of an encrypted data key with an incorrect rsa private key.
 */
int decrypt_data_key_from_bad_rsa_private_key() {
    struct raw_rsa_keyring_test_vector tv = raw_rsa_keyring_test_vectors[0];
    TEST_ASSERT_SUCCESS(set_up_all_the_things(tv.rsa_padding_mode, false));

    struct aws_cryptosdk_edk edk = edk_init_test_vector(&tv);
    aws_array_list_push_back(&edks, (void *)&edk);

    TEST_ASSERT_INT_EQ(
        AWS_OP_SUCCESS,
        aws_cryptosdk_keyring_on_decrypt(kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, tv.alg));
    TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);
    TEST_ASSERT(!aws_array_list_length(&keyring_trace));
    tear_down_all_the_things();
    return 0;
}

/**
 * Test to check for decryption failure of an encrypted data key with a bad rsa padding mode.
 */
int decrypt_data_key_from_bad_rsa_padding_mode() {
    struct raw_rsa_keyring_test_vector tv = raw_rsa_keyring_test_vectors[0];
    /* The correct RSA padding mode for raw_rsa_keyring_test_vectors[0]
     * is AWS_CRYPTOSDK_RSA_PKCS1
     */
    TEST_ASSERT_SUCCESS(set_up_all_the_things(AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1, true));

    struct aws_cryptosdk_edk edk = edk_init_test_vector(&tv);
    aws_array_list_push_back(&edks, (void *)&edk);

    TEST_ASSERT_INT_EQ(
        AWS_OP_SUCCESS,
        aws_cryptosdk_keyring_on_decrypt(kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, NULL, tv.alg));
    TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);
    TEST_ASSERT(!aws_array_list_length(&keyring_trace));
    tear_down_all_the_things();
    return 0;
}

struct test_case raw_rsa_keyring_decrypt_test_cases[] = {
    { "raw_rsa_keyring", "decrypt_data_key_from_test_vectors", decrypt_data_key_from_test_vectors },
    { "raw_rsa_keyring", "decrypt_data_key_from_multiple_edks", decrypt_data_key_from_multiple_edks },
    { "raw_rsa_keyring", "decrypt_data_key_from_bad_edk", decrypt_data_key_from_bad_edk },
    { "raw_rsa_keyring", "decrypt_data_key_from_bad_rsa_private_key", decrypt_data_key_from_bad_rsa_private_key },
    { "raw_rsa_keyring", "decrypt_data_key_from_bad_rsa_padding_mode", decrypt_data_key_from_bad_rsa_padding_mode },
    { NULL }
};
