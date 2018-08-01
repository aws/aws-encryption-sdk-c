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

static int set_up_encrypt_decrypt(enum aws_cryptosdk_aes_key_len raw_key_len,
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

    dec_mat = aws_cryptosdk_decryption_materials_new(alloc, alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    req.enc_context = &enc_context;
    req.alloc = alloc;
    req.alg = alg;

    return 0;
}

static void tear_down_encrypt_decrypt() {
    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_hash_table_clean_up(&enc_context);
    aws_cryptosdk_mk_destroy(mk);
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

struct test_case raw_aes_mk_encrypt_test_cases[] = {
    { "raw_aes_mk", "encrypt_decrypt_data_key", encrypt_decrypt_data_key },
    { "raw_aes_mk", "generate_decrypt_data_key", generate_decrypt_data_key },
    { NULL }
};
