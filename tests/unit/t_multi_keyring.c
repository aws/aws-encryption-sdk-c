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
#include <aws/cryptosdk/materials.h>
#include "testing.h"

struct test_keyring {
    const struct aws_cryptosdk_keyring_vt *vt;
    struct aws_byte_buf decrypted_key_to_return;
    int ret;
    bool generate_or_encrypt_called;
    bool decrypt_called;
};

static void test_keyring_destroy(struct aws_cryptosdk_keyring * kr) {(void)kr;}

static char test_data_key[] = "data key";
static int test_keyring_on_encrypt(
    struct aws_cryptosdk_keyring * kr,
    struct aws_cryptosdk_keyring_on_encrypt_outputs *outputs,
    struct aws_byte_buf *unencrypted_data_key,
    const struct aws_cryptosdk_keyring_on_encrypt_inputs *inputs)
{
    (void)inputs;
    struct test_keyring *self = (struct test_keyring *)kr;

    if (!self->ret) {
        if (!unencrypted_data_key->buffer) {
            *unencrypted_data_key = aws_byte_buf_from_c_str(test_data_key);
        }

        static struct aws_cryptosdk_edk edk;
        edk.enc_data_key = aws_byte_buf_from_c_str("test keyring generate edk");
        edk.provider_id = aws_byte_buf_from_c_str("test keyring generate provider id");
        edk.provider_info = aws_byte_buf_from_c_str("test keyring generate provider info");
        aws_array_list_push_back(outputs->edks, &edk);
    }

    self->generate_or_encrypt_called = true;
    return self->ret;
}

static int test_keyring_on_decrypt(
    struct aws_cryptosdk_keyring * kr,
    struct aws_cryptosdk_keyring_on_decrypt_outputs *outputs,
    const struct aws_cryptosdk_keyring_on_decrypt_inputs *inputs)
{
    (void)inputs;
    struct test_keyring *self = (struct test_keyring *)kr;
    outputs->unencrypted_data_key = self->decrypted_key_to_return;
    self->decrypt_called = true;
    return self->ret;
}

const static struct aws_cryptosdk_keyring_vt test_keyring_vt = {
    .vt_size = sizeof(test_keyring_vt),
    .name = "test keyring",
    .destroy = test_keyring_destroy,
    .on_encrypt = test_keyring_on_encrypt,
    .on_decrypt = test_keyring_on_decrypt
};

static struct aws_allocator * alloc;
// test_keyring[0] used as generator, rest used as children
static struct test_keyring test_keyrings[5];
static const size_t num_test_keyrings = sizeof(test_keyrings)/sizeof(struct test_keyring);
static struct aws_cryptosdk_keyring * multi;

// on_encrypt_inputs struct is not used in test keyring
static struct aws_cryptosdk_keyring_on_encrypt_outputs on_encrypt_outputs;
static struct aws_cryptosdk_keyring_on_decrypt_inputs on_decrypt_inputs;
static struct aws_cryptosdk_keyring_on_decrypt_outputs on_decrypt_outputs = {{0}};

// doesn't matter here, just picking one
//static enum aws_cryptosdk_alg_id alg = AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384;

static int set_up_all_the_things(bool include_generator) {
    alloc = aws_default_allocator();

    static struct aws_array_list edks;
    on_encrypt_outputs.edks = &edks;
    on_decrypt_inputs.edks = &edks;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_edk_list_init(alloc, &edks));

    memset(test_keyrings, 0, sizeof(test_keyrings));
    multi = aws_cryptosdk_multi_keyring_new(alloc, NULL);
    TEST_ASSERT_ADDR_NOT_NULL(multi);
    for (size_t kr_idx = 0; kr_idx < num_test_keyrings; ++kr_idx) {
        test_keyrings[kr_idx].vt = &test_keyring_vt;

        if (kr_idx) {
            TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_keyring_add(
                                    multi,
                                    (struct aws_cryptosdk_keyring *)(test_keyrings + kr_idx)));
        } else if (include_generator) {
            TEST_ASSERT_SUCCESS(aws_cryptosdk_multi_keyring_set_generator(
                                    multi,
                                    (struct aws_cryptosdk_keyring *)(test_keyrings)));
        }

        // all flags have been reset
        TEST_ASSERT(!test_keyrings[kr_idx].generate_or_encrypt_called);
        TEST_ASSERT(!test_keyrings[kr_idx].decrypt_called);
    }

    return 0;
}

static void tear_down_all_the_things() {
    aws_cryptosdk_keyring_destroy(multi);
    // same list in on_encrypt_outputs and on_decrypt_inputs, just clean it up once
    aws_cryptosdk_edk_list_clean_up(on_encrypt_outputs.edks);
    aws_byte_buf_clean_up(&on_decrypt_outputs.unencrypted_data_key);
}

int delegates_on_encrypt_calls() {
    struct aws_byte_buf test_data_key_buf = aws_byte_buf_from_c_str(test_data_key);
    struct aws_byte_buf empty_buf = {0};

    for (int use_generator = 0; use_generator < 2; ++use_generator) {
        TEST_ASSERT_SUCCESS(set_up_all_the_things(use_generator));

        struct aws_byte_buf * unencrypted_data_key = use_generator ? &empty_buf : &test_data_key_buf;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
                                multi,
                                &on_encrypt_outputs,
                                unencrypted_data_key,
                                NULL));
        TEST_ASSERT_ADDR_NOT_NULL(unencrypted_data_key->buffer);

        int starting_idx = use_generator ^ 1;
        for (size_t kr_idx = starting_idx; kr_idx < num_test_keyrings; ++kr_idx) {
            TEST_ASSERT(test_keyrings[kr_idx].generate_or_encrypt_called);
        }

        TEST_ASSERT_INT_EQ(aws_array_list_length(on_encrypt_outputs.edks),
                           num_test_keyrings - starting_idx);

        tear_down_all_the_things();
    }
    return 0;
}

int generator_set_but_not_called_when_data_key_present() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things(true));
    struct aws_byte_buf unencrypted_data_key = aws_byte_buf_from_c_str(test_data_key);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_encrypt(
                            multi,
                            &on_encrypt_outputs,
                            &unencrypted_data_key,
                            NULL));

    TEST_ASSERT(!test_keyrings[0].generate_or_encrypt_called);
    for (size_t kr_idx = 1; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].generate_or_encrypt_called);
    }
    TEST_ASSERT_INT_EQ(aws_array_list_length(on_encrypt_outputs.edks), num_test_keyrings - 1);

    tear_down_all_the_things();
    return 0;
}

int on_encrypt_fails_when_generator_not_set_and_no_data_key() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things(false));
    struct aws_byte_buf unencrypted_data_key = {0};

    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_STATE,
                      aws_cryptosdk_keyring_on_encrypt(multi,
                                                       &on_encrypt_outputs,
                                                       &unencrypted_data_key,
                                                       NULL));

    for (size_t kr_idx = 1; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(!test_keyrings[kr_idx].generate_or_encrypt_called);
    }

    tear_down_all_the_things();
    return 0;
}

int fail_on_failed_child_encrypt_and_stop() {
    for (size_t bad_keyring_idx = 0; bad_keyring_idx < num_test_keyrings; ++bad_keyring_idx) {
        TEST_ASSERT_SUCCESS(set_up_all_the_things(true));
        struct aws_byte_buf unencrypted_data_key = {0};

        test_keyrings[bad_keyring_idx].ret = AWS_OP_ERR;

        TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_on_encrypt(
                               multi,
                               &on_encrypt_outputs,
                               &unencrypted_data_key,
                               NULL));

        size_t kr_idx = 0;
        for (; kr_idx <= bad_keyring_idx; ++kr_idx) {
            TEST_ASSERT(test_keyrings[kr_idx].generate_or_encrypt_called);
        }
        for (; kr_idx < num_test_keyrings; ++kr_idx) {
            TEST_ASSERT(!test_keyrings[kr_idx].generate_or_encrypt_called);
        }

        TEST_ASSERT_INT_EQ(aws_array_list_length(on_encrypt_outputs.edks), 0);

        tear_down_all_the_things();
    }
    return 0;
}

static size_t already_there_list_len = 7;
static struct aws_cryptosdk_edk already_there_edk;
static int put_stuff_in_edk_list() {
    already_there_edk.enc_data_key = aws_byte_buf_from_c_str("already there edk");
    already_there_edk.provider_id = aws_byte_buf_from_c_str("already there provider id");
    already_there_edk.provider_info = aws_byte_buf_from_c_str("already there provider info");
    for (size_t idx = 0; idx < already_there_list_len; ++idx) {
        TEST_ASSERT_SUCCESS(aws_array_list_push_back(on_encrypt_outputs.edks,
                                                     &already_there_edk));
    }
    return 0;
}

static int check_edk_list_unchanged() {
    TEST_ASSERT_INT_EQ(aws_array_list_length(on_encrypt_outputs.edks), already_there_list_len);
    for (size_t idx = 0; idx < already_there_list_len; ++idx) {
        struct aws_cryptosdk_edk *my_edk;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(on_encrypt_outputs.edks, (void **)&my_edk, idx));
        TEST_ASSERT(aws_cryptosdk_edk_eq(&already_there_edk, my_edk));
    }
    return 0;
}

int failed_encrypt_keeps_edk_list_intact() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things(true));
    struct aws_byte_buf unencrypted_data_key = {0};

    TEST_ASSERT_SUCCESS(put_stuff_in_edk_list());

    const size_t bad_keyring_idx = 4;
    test_keyrings[bad_keyring_idx].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_on_encrypt(
                           multi,
                           &on_encrypt_outputs,
                           &unencrypted_data_key,
                           NULL));

    TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);
    TEST_ASSERT_SUCCESS(check_edk_list_unchanged());

    tear_down_all_the_things();
    return 0;
}

int fail_on_failed_generate_and_stop() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things(true));
    struct aws_byte_buf unencrypted_data_key = {0};

    test_keyrings[0].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_on_encrypt(
                           multi,
                           &on_encrypt_outputs,
                           &unencrypted_data_key,
                           NULL));

    TEST_ASSERT(test_keyrings[0].generate_or_encrypt_called);
    for (size_t kr_idx = 1; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(!test_keyrings[kr_idx].generate_or_encrypt_called);
    }

    TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);
    TEST_ASSERT_INT_EQ(aws_array_list_length(on_encrypt_outputs.edks), 0);

    tear_down_all_the_things();
    return 0;
}

int delegates_decrypt_calls() {
    for (int use_generator = 0; use_generator < 2; ++use_generator) {
        TEST_ASSERT_SUCCESS(set_up_all_the_things(use_generator));

        test_keyrings[2].ret = AWS_OP_ERR;

        const size_t successful_keyring = 3;

        char my_data_key[] = "Eureka!";
        test_keyrings[successful_keyring].decrypted_key_to_return = aws_byte_buf_from_c_str(my_data_key);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(multi, 
                                                             &on_decrypt_outputs,
                                                             &on_decrypt_inputs));
        TEST_ASSERT_ADDR_EQ(on_decrypt_outputs.unencrypted_data_key.buffer, my_data_key);

        size_t kr_idx = use_generator ^ 1;
        for (; kr_idx <= successful_keyring; ++kr_idx) {
            TEST_ASSERT(test_keyrings[kr_idx].decrypt_called);
        }
        for (; kr_idx < num_test_keyrings; ++kr_idx) {
            TEST_ASSERT(!test_keyrings[kr_idx].decrypt_called);
        } 

        tear_down_all_the_things();
    }
    return 0;
}

int succeed_when_no_error_and_no_decrypt() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things(true));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_keyring_on_decrypt(multi,
                                                         &on_decrypt_outputs,
                                                         &on_decrypt_inputs));
    TEST_ASSERT_ADDR_NULL(on_decrypt_outputs.unencrypted_data_key.buffer);

    for (size_t kr_idx = 0; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].decrypt_called);
    }

    tear_down_all_the_things();
    return 0;
}

int fail_when_error_and_no_decrypt() {
    TEST_ASSERT_SUCCESS(set_up_all_the_things(true));

    test_keyrings[2].ret = AWS_OP_ERR;

    TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_keyring_on_decrypt(multi,
                                                                    &on_decrypt_outputs,
                                                                    &on_decrypt_inputs));
    TEST_ASSERT_ADDR_NULL(unencrypted_data_key.buffer);

    for (size_t kr_idx = 0; kr_idx < num_test_keyrings; ++kr_idx) {
        TEST_ASSERT(test_keyrings[kr_idx].decrypt_called);
    }

    tear_down_all_the_things();
    return 0;
}

struct test_case multi_keyring_test_cases[] = {
    { "multi_keyring", "delegates_on_encrypt_calls", delegates_on_encrypt_calls },
    { "multi_keyring", "generator_set_but_not_called_when_data_key_present",
      generator_set_but_not_called_when_data_key_present },
    { "multi_keyring", "on_encrypt_fails_when_generator_not_set_and_no_data_key",
      on_encrypt_fails_when_generator_not_set_and_no_data_key },
    { "multi_keyring", "fail_on_failed_child_encrypt_and_stop", fail_on_failed_child_encrypt_and_stop },
    { "multi_keyring", "failed_encrypt_keeps_edk_list_intact", failed_encrypt_keeps_edk_list_intact },
    { "multi_keyring", "fail_on_failed_generate_and_stop", fail_on_failed_generate_and_stop },
    { "multi_keyring", "delegates_decrypt_calls", delegates_decrypt_calls },
    { "multi_keyring", "succeed_when_no_error_and_no_decrypt", succeed_when_no_error_and_no_decrypt },
    { "multi_keyring", "fail_when_error_and_no_decrypt", fail_when_error_and_no_decrypt },
    { NULL }
};
