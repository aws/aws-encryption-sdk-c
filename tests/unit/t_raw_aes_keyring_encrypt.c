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
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/raw_aes_keyring.h>
#include "raw_aes_keyring_test_vectors.h"
#include "testing.h"

static struct aws_allocator *alloc;
static struct aws_cryptosdk_keyring *kr;
static struct aws_hash_table enc_ctx;
static struct aws_array_list keyring_trace;
static struct aws_array_list edks;
static struct aws_byte_buf unencrypted_data_key = { 0 };
// same key, after it has been encrypted and then decrypted
static struct aws_byte_buf decrypted_data_key = { 0 };

static int put_stuff_in_encryption_context() {
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_key_1, "Easy come easy go.");
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_val_1, "Will you let me go?");
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_key_2, "Bismillah! No we will not let you go!");
    AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_val_2, "Let him go!");
    struct aws_hash_element *elem;
    TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_ctx, (void *)enc_ctx_key_1, &elem, NULL));
    elem->value = (void *)enc_ctx_val_1;
    TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_ctx, (void *)enc_ctx_key_2, &elem, NULL));
    elem->value = (void *)enc_ctx_val_2;

    return 0;
}

static int set_up_all_the_things(enum aws_cryptosdk_aes_key_len raw_key_len, bool fill_enc_ctx) {
    alloc = aws_default_allocator();
    kr    = raw_aes_keyring_tv_new(alloc, raw_key_len);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(alloc, &enc_ctx));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_trace_init(alloc, &keyring_trace));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &edks));

    if (fill_enc_ctx) TEST_ASSERT_SUCCESS(put_stuff_in_encryption_context());

    return 0;
}

static void tear_down_all_the_things() {
    aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);
    aws_cryptosdk_keyring_trace_clean_up(&keyring_trace);
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_edk_list_clean_up(&edks);
    aws_byte_buf_clean_up(&unencrypted_data_key);
    aws_byte_buf_clean_up(&decrypted_data_key);
}

static enum aws_cryptosdk_aes_key_len raw_key_lens[] = {
    AWS_CRYPTOSDK_AES128, AWS_CRYPTOSDK_AES192, AWS_CRYPTOSDK_AES256
};
static enum aws_cryptosdk_alg_id algs[] = {
    ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256, ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256, ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
};

static int encrypt_decrypt_data_key() {
    for (int fill_enc_ctx = 0; fill_enc_ctx < 2; ++fill_enc_ctx) {
        for (int key_len_idx = 0; key_len_idx < sizeof(raw_key_lens) / sizeof(enum aws_cryptosdk_aes_key_len);
             ++key_len_idx) {
            for (int alg_idx = 0; alg_idx < sizeof(algs) / sizeof(enum aws_cryptosdk_alg_id); ++alg_idx) {
                TEST_ASSERT_SUCCESS(set_up_all_the_things(raw_key_lens[key_len_idx], fill_enc_ctx));

                const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(algs[alg_idx]);
                TEST_ASSERT_SUCCESS(aws_byte_buf_init(&unencrypted_data_key, alloc, props->data_key_len));
                memset(unencrypted_data_key.buffer, 0x77, props->data_key_len);
                unencrypted_data_key.len = unencrypted_data_key.capacity;

                TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
                    kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, &enc_ctx, algs[alg_idx]));
                TEST_ASSERT_INT_EQ(aws_array_list_length(&edks), 1);
                TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                    &keyring_trace,
                    AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX | AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY));

                TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
                    kr, alloc, &decrypted_data_key, &keyring_trace, &edks, &enc_ctx, algs[alg_idx]));
                TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &decrypted_data_key));
                TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                    &keyring_trace,
                    AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX | AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));

                tear_down_all_the_things();
            }
        }
    }
    return 0;
}

static int generate_decrypt_data_key() {
    for (int fill_enc_ctx = 0; fill_enc_ctx < 2; ++fill_enc_ctx) {
        for (int key_len_idx = 0; key_len_idx < sizeof(raw_key_lens) / sizeof(enum aws_cryptosdk_aes_key_len);
             ++key_len_idx) {
            for (int alg_idx = 0; alg_idx < sizeof(algs) / sizeof(enum aws_cryptosdk_alg_id); ++alg_idx) {
                TEST_ASSERT_SUCCESS(set_up_all_the_things(raw_key_lens[key_len_idx], fill_enc_ctx));

                TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
                    kr, alloc, &unencrypted_data_key, &keyring_trace, &edks, &enc_ctx, algs[alg_idx]));
                TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key.buffer);
                TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                    &keyring_trace,
                    AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX | AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY |
                        AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY));

                const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(algs[alg_idx]);
                TEST_ASSERT_INT_EQ(unencrypted_data_key.len, props->data_key_len);
                TEST_ASSERT_INT_EQ(aws_array_list_length(&edks), 1);

                TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(
                    kr, alloc, &decrypted_data_key, &keyring_trace, &edks, &enc_ctx, algs[alg_idx]));
                TEST_ASSERT(aws_byte_buf_eq(&unencrypted_data_key, &decrypted_data_key));
                TEST_ASSERT_SUCCESS(raw_aes_keyring_tv_trace_updated_properly(
                    &keyring_trace,
                    AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX | AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY));

                tear_down_all_the_things();
            }
        }
    }
    return 0;
}

/**
 * Data key encryption with set of known test vectors. This set includes wrapping keys of
 * 256, 192, and 128 bits. Same vectors as used in decrypt_data_key_test_vectors.
 */
static int encrypt_data_key_test_vectors() {
    uint8_t data_key_dup[32];  // 32 = max data key length

    for (struct raw_aes_keyring_test_vector *tv = raw_aes_keyring_test_vectors; tv->data_key; ++tv) {
        const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(tv->alg);

        TEST_ASSERT_SUCCESS(set_up_all_the_things(tv->raw_key_len, false));
        TEST_ASSERT_SUCCESS(set_test_vector_encryption_context(alloc, &enc_ctx, tv));

        // copy from constant memory because cleanup needs to zero it out
        memcpy(data_key_dup, tv->data_key, props->data_key_len);
        unencrypted_data_key = aws_byte_buf_from_array(data_key_dup, props->data_key_len);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_raw_aes_keyring_encrypt_data_key_with_iv(
            kr, alloc, &unencrypted_data_key, &edks, &enc_ctx, tv->alg, tv->iv));
        TEST_ASSERT_INT_EQ(aws_array_list_length(&edks), 1);
        // Note: the test entry function for encryption with fixed IV does not write to the
        // trace so we don't test for it here.

        struct aws_cryptosdk_edk edk;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at(&edks, (void *)&edk, 0));

        struct aws_cryptosdk_edk known_answer = edk_init_from_test_vector(tv);
        TEST_ASSERT(aws_cryptosdk_edk_eq(&edk, &known_answer));

        aws_cryptosdk_edk_clean_up(&known_answer);
        tear_down_all_the_things();
    }
    return 0;
}

static int fail_on_disallowed_namespace() {
    AWS_STATIC_STRING_FROM_LITERAL(key_namespace, "aws-kms");
    TEST_ASSERT_ADDR_NULL(aws_cryptosdk_raw_aes_keyring_new(NULL, key_namespace, NULL, NULL, 0));
    TEST_ASSERT_INT_EQ(aws_last_error(), AWS_CRYPTOSDK_ERR_RESERVED_NAME);
    return 0;
}

struct test_case raw_aes_keyring_encrypt_test_cases[] = {
    { "raw_aes_keyring", "encrypt_decrypt_data_key", encrypt_decrypt_data_key },
    { "raw_aes_keyring", "generate_decrypt_data_key", generate_decrypt_data_key },
    { "raw_aes_keyring", "encrypt_data_key_test_vectors", encrypt_data_key_test_vectors },
    { "raw_aes_keyring", "fail_on_disallowed_namespace", fail_on_disallowed_namespace },
    { NULL }
};
