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

#include "test_keyring.h"
#include "../unit/testing.h"

static void test_keyring_destroy(struct aws_cryptosdk_keyring * kr) {
    struct test_keyring *self = (struct test_keyring *)kr;
    self->destroy_called = true;
}

static int test_keyring_on_encrypt(struct aws_cryptosdk_keyring *kr,
                                   struct aws_allocator *request_alloc,
                                   struct aws_byte_buf *unencrypted_data_key,
                                   struct aws_array_list *edks,
                                   const struct aws_hash_table *enc_context,
                                   enum aws_cryptosdk_alg_id alg)
{
    (void)enc_context;
    (void)request_alloc;
    struct test_keyring *self = (struct test_keyring *)kr;

    if (!self->ret && !self->skip_output) {
        if (!unencrypted_data_key->buffer) {
            *unencrypted_data_key = self->generated_data_key_to_return;
        }

        static struct aws_cryptosdk_edk edk;
        edk.enc_data_key = aws_byte_buf_from_c_str("test keyring generate edk");
        edk.provider_id = aws_byte_buf_from_c_str("test keyring generate provider id");
        edk.provider_info = aws_byte_buf_from_c_str("test keyring generate provider info");
        aws_array_list_push_back(edks, &edk);
    }

    self->on_encrypt_called = true;
    return self->ret;
}

static int test_keyring_on_decrypt(struct aws_cryptosdk_keyring *kr,
                                   struct aws_allocator *request_alloc,
                                   struct aws_byte_buf *unencrypted_data_key,
                                   const struct aws_array_list *edks,
                                   const struct aws_hash_table *enc_context,
                                   enum aws_cryptosdk_alg_id alg) {
    (void)edks;
    (void)enc_context;
    (void)alg;
    (void)request_alloc;
    struct test_keyring *self = (struct test_keyring *)kr;
    if (!self->ret && !self->skip_output) {
        *unencrypted_data_key = self->decrypted_data_key_to_return;
    }
    self->on_decrypt_called = true;
    return self->ret;
}

const struct aws_cryptosdk_keyring_vt test_keyring_vt = {
    .vt_size = sizeof(test_keyring_vt),
    .name = "test keyring",
    .destroy = test_keyring_destroy,
    .on_encrypt = test_keyring_on_encrypt,
    .on_decrypt = test_keyring_on_decrypt
};

int test_keyring_datakey_decrypt(struct aws_byte_buf *result_output,
                                 struct aws_cryptosdk_keyring *keyring,
                                 struct aws_cryptosdk_edk *edk,
                                 struct aws_hash_table *enc_context,
                                 enum aws_cryptosdk_alg_id alg) {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_array_list encrypted_data_keys;

    TEST_ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk)));
    aws_array_list_push_back(&encrypted_data_keys, (void *) edk);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(keyring,
                                                         alloc,
                                                         result_output,
                                                         &encrypted_data_keys,
                                                         enc_context,
                                                         alg));
    aws_array_list_clean_up(&encrypted_data_keys);
    return 0;
}

int test_keyring_datakey_encrypt(struct aws_array_list *result_output,
                                 struct aws_cryptosdk_keyring *keyring,
                                 const char *plain_text,
                                 struct aws_hash_table *enc_context,
                                 enum aws_cryptosdk_alg_id alg) {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_byte_buf unencrypted_data_key = aws_byte_buf_from_c_str(plain_text);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, result_output));
    TEST_ASSERT_INT_EQ(0, result_output->length);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(keyring,
                                                         alloc,
                                                         &unencrypted_data_key,
                                                         result_output,
                                                         enc_context,
                                                         alg));
    TEST_ASSERT(result_output->length > 0);
    return 0;
}

int test_keyring_datakey_decrypt_and_compare_with_pt(const struct aws_byte_buf *expected_plain_text,
                                                     struct aws_cryptosdk_keyring *keyring,
                                                     struct aws_cryptosdk_edk *edk,
                                                     struct aws_hash_table *enc_context,
                                                     enum aws_cryptosdk_alg_id alg) {
    struct aws_byte_buf result_output = {.buffer= NULL, .len = 0, .allocator = NULL};
    TEST_ASSERT_SUCCESS(test_keyring_datakey_decrypt(&result_output, keyring, edk, enc_context, alg));
    TEST_ASSERT(aws_byte_buf_eq(&result_output, expected_plain_text));
    aws_byte_buf_clean_up(&result_output);
    return 0;
}

int test_keyring_datakey_decrypt_and_compare_with_c_str_pt(const char *expected_plain_text,
                                                           struct aws_cryptosdk_keyring *keyring,
                                                           struct aws_cryptosdk_edk *edk,
                                                           struct aws_hash_table *enc_context,
                                                           enum aws_cryptosdk_alg_id alg) {
    struct aws_byte_buf expected_pt_bb = aws_byte_buf_from_c_str(expected_plain_text);
    return test_keyring_datakey_decrypt_and_compare_with_pt(&expected_pt_bb, keyring, edk, enc_context, alg);
}

