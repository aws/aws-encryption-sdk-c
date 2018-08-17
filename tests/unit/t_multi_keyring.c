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
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/private/materials.h>
#include "testing.h"

struct test_keyring {
    const struct aws_cryptosdk_keyring_vt *vt;

    struct aws_byte_buf decrypted_key_to_return;

    int ret;

    bool generate_called;
    bool encrypt_called;
    bool decrypt_called;
};

static void test_keyring_destroy(struct aws_cryptosdk_keyring * kr) {(void)kr;}

static int test_keyring_generate_data_key(struct aws_cryptosdk_keyring * kr,
                                     struct aws_cryptosdk_encryption_materials * enc_mat) {
    (void)enc_mat;
    struct test_keyring *self = (struct test_keyring *)kr;

    if (!self->ret) {
        static char data_key[] = "data key";
        enc_mat->unencrypted_data_key = aws_byte_buf_from_c_str(data_key);

        static struct aws_cryptosdk_edk edk;
        edk.enc_data_key = aws_byte_buf_from_c_str("test keyring generate edk");
        edk.provider_id = aws_byte_buf_from_c_str("test keyring generate provider id");
        edk.provider_id = aws_byte_buf_from_c_str("test keyring generate provider info");
        aws_array_list_push_back(&enc_mat->encrypted_data_keys, &edk);
    }

    self->generate_called = true;
    return self->ret;
}

static int test_keyring_encrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                    struct aws_cryptosdk_encryption_materials * enc_mat) {
    (void)enc_mat;
    struct test_keyring *self = (struct test_keyring *)kr;

    if (!self->ret) {
        static struct aws_cryptosdk_edk edk;
        edk.enc_data_key = aws_byte_buf_from_c_str("test keyring encrypt edk");
        edk.provider_id = aws_byte_buf_from_c_str("test keyring encrypt provider id");
        edk.provider_id = aws_byte_buf_from_c_str("test keyring encrypt provider info");
        aws_array_list_push_back(&enc_mat->encrypted_data_keys, &edk);
    }

    self->encrypt_called = true;
    return self->ret;
}

static int test_keyring_decrypt_data_key(struct aws_cryptosdk_keyring * kr,
                                    struct aws_cryptosdk_decryption_materials * dec_mat,
                                    const struct aws_cryptosdk_decryption_request * request) {
    (void)dec_mat;
    (void)request;
    struct test_keyring *self = (struct test_keyring *)kr;
    dec_mat->unencrypted_data_key = self->decrypted_key_to_return;
    self->decrypt_called = true;
    return self->ret;
}

const static struct aws_cryptosdk_keyring_vt test_keyring_vt = {
    .vt_size = sizeof(test_keyring_vt),
    .name = "test keyring",
    .destroy = test_keyring_destroy,
    .generate_data_key = test_keyring_generate_data_key,
    .encrypt_data_key = test_keyring_encrypt_data_key,
    .decrypt_data_key = test_keyring_decrypt_data_key
};

static struct aws_allocator * alloc;
static struct test_keyring test_keyrings[5];
static const size_t num_test_keyrings = sizeof(test_keyrings)/sizeof(struct test_keyring);
static struct aws_cryptosdk_keyring * multi;
static struct aws_cryptosdk_encryption_materials * enc_mat;
static struct aws_cryptosdk_decryption_materials * dec_mat;
static struct aws_cryptosdk_decryption_request dec_req;

static int set_up_all_the_things() {
    alloc = aws_default_allocator();

    // doesn't matter here, just picking one
    enum aws_cryptosdk_alg_id alg = AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384;

    enc_mat = aws_cryptosdk_encryption_materials_new(alloc, alg);
    dec_mat = aws_cryptosdk_decryption_materials_new(alloc, alg);
    TEST_ASSERT_ADDR_NOT_NULL(enc_mat);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    memset(test_keyrings, 0, sizeof(test_keyrings));
    multi = aws_cryptosdk_multi_keyring_new(alloc);
    TEST_ASSERT_ADDR_NOT_NULL(multi);
    for (size_t kr_idx = 0; kr_idx < num_test_keyrings; ++kr_idx) {
        test_keyrings[kr_idx].vt = &test_keyring_vt;
        TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_keyring_add(
                                multi,
                                (struct aws_cryptosdk_keyring *)(test_keyrings + kr_idx)));

        // all flags have been reset
        TEST_ASSERT(!test_keyrings[kr_idx].generate_called);
        TEST_ASSERT(!test_keyrings[kr_idx].encrypt_called);
        TEST_ASSERT(!test_keyrings[kr_idx].decrypt_called);
    }

    return 0;
}

static void tear_down_all_the_things() {
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_cryptosdk_keyring_destroy(multi);
}

int delegates_encrypt_calls() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_encrypt_data_key(multi, enc_mat));

    for (size_t kr_idx = 0; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].encrypt_called);
    }

    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), num_test_keyrings);

    tear_down_all_the_things();
    return 0;
}

int delegates_generate_calls() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_generate_data_key(multi, enc_mat));

    TEST_ASSERT(test_keyrings[0].generate_called);
    TEST_ASSERT(!test_keyrings[0].encrypt_called);

    for (size_t kr_idx = 1; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].encrypt_called);
        TEST_ASSERT(!test_keyrings[kr_idx].generate_called);
    }

    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), num_test_keyrings);

    tear_down_all_the_things();
    return 0;
}

int fail_on_failed_encrypt_and_stop() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    const size_t bad_keyring_idx = 2;
    test_keyrings[bad_keyring_idx].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_encrypt_data_key(multi, enc_mat));

    size_t kr_idx = 0;
    for (; kr_idx <= bad_keyring_idx; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].encrypt_called);
    }
    for (; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(!test_keyrings[kr_idx].encrypt_called);
    }

    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 0);

    tear_down_all_the_things();
    return 0;
}

static size_t already_there_list_len = 7;
static struct aws_cryptosdk_edk already_there_edk;
static int put_stuff_in_edk_list() {
    already_there_edk.enc_data_key = aws_byte_buf_from_c_str("already there edk");
    already_there_edk.provider_id = aws_byte_buf_from_c_str("already there provider id");
    already_there_edk.provider_info = aws_byte_buf_from_c_str("already there provider info");
    for (size_t idx = 0; idx < already_there_list_len; ++idx) {
        TEST_ASSERT_SUCCESS(aws_array_list_push_back(&enc_mat->encrypted_data_keys,
                                                     &already_there_edk));
    }
    return 0;
}

static int check_edk_list_unchanged() {
    for (size_t idx = 0; idx < already_there_list_len; ++idx) {
        struct aws_cryptosdk_edk * my_edk;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&enc_mat->encrypted_data_keys, (void **)&my_edk, idx));
        TEST_ASSERT(aws_cryptosdk_edk_eq(&already_there_edk, my_edk));
    }
    return 0;
}

int failed_encrypt_keeps_edk_list_intact() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());
    TEST_ASSERT_SUCCESS(put_stuff_in_edk_list());

    const size_t bad_keyring_idx = 4;
    test_keyrings[bad_keyring_idx].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_encrypt_data_key(multi, enc_mat));

    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), already_there_list_len);
    TEST_ASSERT_SUCCESS(check_edk_list_unchanged());

    tear_down_all_the_things();
    return 0;
}

int failed_encrypt_within_generate() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    const size_t bad_keyring_idx = 3;
    test_keyrings[bad_keyring_idx].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_generate_data_key(multi, enc_mat));

    TEST_ASSERT(test_keyrings[0].generate_called);
    TEST_ASSERT(!test_keyrings[0].encrypt_called);

    size_t kr_idx;
    for (kr_idx = 1; kr_idx <= bad_keyring_idx; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].encrypt_called);
        TEST_ASSERT(!test_keyrings[kr_idx].generate_called);
    }

    for (; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(!test_keyrings[kr_idx].encrypt_called);
        TEST_ASSERT(!test_keyrings[kr_idx].generate_called);
    }

    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 0);

    tear_down_all_the_things();
    return 0;

}

int fail_on_failed_generate_and_stop() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    test_keyrings[0].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_generate_data_key(multi, enc_mat));

    TEST_ASSERT(test_keyrings[0].generate_called);
    TEST_ASSERT(!test_keyrings[0].encrypt_called);

    for (size_t kr_idx = 1; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(!test_keyrings[kr_idx].generate_called);
        TEST_ASSERT(!test_keyrings[kr_idx].encrypt_called);
    }

    TEST_ASSERT_INT_EQ(aws_array_list_length(&enc_mat->encrypted_data_keys), 0);

    tear_down_all_the_things();
    return 0;
}

int delegates_decrypt_calls() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    test_keyrings[2].ret = AWS_OP_ERR;

    const size_t successful_keyring = 3;

    char data_key[] = "Eureka!";
    test_keyrings[successful_keyring].decrypted_key_to_return = aws_byte_buf_from_c_str(data_key);

    struct aws_cryptosdk_decryption_request req;
    req.alloc = alloc;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_decrypt_data_key(multi, dec_mat, &req));
    TEST_ASSERT_ADDR_EQ(dec_mat->unencrypted_data_key.buffer, data_key);

    size_t kr_idx = 0;
    for (; kr_idx <= successful_keyring; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].decrypt_called);
    }
    for (; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(!test_keyrings[kr_idx].decrypt_called);
    } 

    tear_down_all_the_things();
    return 0;
}

int succeed_when_no_error_and_no_decrypt() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_decrypt_data_key(multi, dec_mat, &dec_req));
    TEST_ASSERT_ADDR_NULL(dec_mat->unencrypted_data_key.buffer);

    for (size_t kr_idx = 0; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].decrypt_called);
    }

    tear_down_all_the_things();
    return 0;
}

int fail_when_error_and_no_decrypt() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things());

    test_keyrings[2].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_decrypt_data_key(multi, dec_mat, &dec_req));
    TEST_ASSERT_ADDR_NULL(dec_mat->unencrypted_data_key.buffer);

    for (size_t kr_idx = 0; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].decrypt_called);
    }

    tear_down_all_the_things();
    return 0;
}

struct test_case multi_keyring_test_cases[] = {
    { "multi_keyring", "delegates_encrypt_calls", delegates_encrypt_calls },
    { "multi_keyring", "fail_on_failed_encrypt_and_stop", fail_on_failed_encrypt_and_stop },
    { "multi_keyring", "failed_encrypt_keeps_edk_list_intact", failed_encrypt_keeps_edk_list_intact },
    { "multi_keyring", "failed_encrypt_within_generate", failed_encrypt_within_generate },
    { "multi_keyring", "fail_on_failed_generate_and_stop", fail_on_failed_generate_and_stop },
    { "multi_keyring", "delegates_generate_calls", delegates_generate_calls },
    { "multi_keyring", "delegates_decrypt_calls", delegates_decrypt_calls },
    { "multi_keyring", "fail_when_error_and_no_decrypt", fail_when_error_and_no_decrypt },
    { NULL }
};
