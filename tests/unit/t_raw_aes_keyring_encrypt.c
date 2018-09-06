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
#include <aws/cryptosdk/private/raw_aes_keyring.h>
#include <aws/cryptosdk/private/materials.h>
#include "raw_aes_keyring_test_vectors.h"
#include "testing.h"

#if 0

static struct aws_allocator * alloc;
static struct aws_cryptosdk_keyring * kr;
static struct aws_hash_table enc_context;
static struct aws_cryptosdk_encryption_materials * enc_mat;
static struct aws_cryptosdk_decryption_request req;
static struct aws_cryptosdk_decryption_materials * dec_mat;

static int put_stuff_in_encryption_context() {
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_1, "Easy come easy go.");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_1, "Will you let me go?");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_2, "Bismillah! No we will not let you go!");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_2, "Let him go!");
    struct aws_hash_element * elem;
    TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_context, (void *)enc_context_key_1, &elem, NULL));
    elem->value = (void *)enc_context_val_1;
    TEST_ASSERT_SUCCESS(aws_hash_table_create(&enc_context, (void *)enc_context_key_2, &elem, NULL));
    elem->value = (void *)enc_context_val_2;

    return 0;
}

static int set_up_encrypt(enum aws_cryptosdk_aes_key_len raw_key_len,
                          enum aws_cryptosdk_alg_id alg) {
    alloc = aws_default_allocator();
    kr = raw_aes_keyring_tv_new(alloc, raw_key_len);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    TEST_ASSERT_SUCCESS(aws_hash_table_init(&enc_context, alloc, 5, aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy));

    enc_mat = aws_cryptosdk_encryption_materials_new(alloc, alg);
    TEST_ASSERT_ADDR_NOT_NULL(enc_mat);
    enc_mat->enc_context = &enc_context;

    return 0;
}

static int set_up_encrypt_decrypt(enum aws_cryptosdk_aes_key_len raw_key_len,
                                  enum aws_cryptosdk_alg_id alg,
                                  bool fill_enc_context) {
    TEST_ASSERT_SUCCESS(set_up_encrypt(raw_key_len, alg));

    if (fill_enc_context) TEST_ASSERT_SUCCESS(put_stuff_in_encryption_context());

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
    aws_cryptosdk_keyring_destroy(kr);
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
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_decrypt_data_key(kr, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_INT_EQ(dec_mat->unencrypted_data_key.len, enc_mat->unencrypted_data_key.len);
    TEST_ASSERT(!memcmp(dec_mat->unencrypted_data_key.buffer, enc_mat->unencrypted_data_key.buffer, dec_mat->unencrypted_data_key.len));

    return 0;
}

static enum aws_cryptosdk_aes_key_len raw_key_lens[] = {AWS_CRYPTOSDK_AES_128, AWS_CRYPTOSDK_AES_192, AWS_CRYPTOSDK_AES_256};
static enum aws_cryptosdk_alg_id algs[] = {AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
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

                TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_encrypt_data_key(kr, enc_mat));
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

                TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_generate_data_key(kr, enc_mat));
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
 * Data key encryption with set of known test vectors. This set includes wrapping keys of
 * 256, 192, and 128 bits. Same vectors as used in decrypt_data_key_test_vectors.
 */
int encrypt_data_key_test_vectors() {
    uint8_t data_key_dup[32]; // 32 = max data key length

    for (struct raw_aes_keyring_test_vector * tv = raw_aes_keyring_test_vectors; tv->data_key; ++tv) {
        const struct aws_cryptosdk_alg_properties * props = aws_cryptosdk_alg_props(tv->alg);

        TEST_ASSERT_SUCCESS(set_up_encrypt(tv->raw_key_len, tv->alg));
        TEST_ASSERT_SUCCESS(set_test_vector_encryption_context(alloc, &enc_context, tv));

        // copy from constant memory because cleanup needs to zero it out
        memcpy(data_key_dup, tv->data_key, props->data_key_len);

        enc_mat->unencrypted_data_key = aws_byte_buf_from_array(data_key_dup, props->data_key_len);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_raw_aes_keyring_encrypt_data_key_with_iv(kr, enc_mat, tv->iv));
        TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 1);

        struct aws_cryptosdk_edk edk;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at(&enc_mat->encrypted_data_keys, (void *)&edk, 0));

        struct aws_cryptosdk_edk known_answer = edk_init_from_test_vector(tv);
        TEST_ASSERT(aws_cryptosdk_edk_eq(&edk, &known_answer));

        aws_cryptosdk_edk_clean_up(&known_answer);
        tear_down_encrypt();
    }
    return 0;
}

#endif // #if 0

struct test_case raw_aes_keyring_encrypt_test_cases[] = {
/*
    { "raw_aes_keyring", "encrypt_decrypt_data_key", encrypt_decrypt_data_key },
    { "raw_aes_keyring", "generate_decrypt_data_key", generate_decrypt_data_key },
    { "raw_aes_keyring", "encrypt_data_key_test_vectors", encrypt_data_key_test_vectors },
*/
    { NULL }
};
