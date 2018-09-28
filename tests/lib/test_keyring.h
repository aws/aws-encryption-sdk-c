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

#ifndef AWS_CRYPTOSDK_TESTS_LIB_TEST_KEYRING_H
#define AWS_CRYPTOSDK_TESTS_LIB_TEST_KEYRING_H

#include <aws/cryptosdk/materials.h>

/* FIXME: Refactor this later.
 *
 * This test keyring was used as a generic mock of a keyring for the multi keyring
 * tests. Moving it into tests/lib so that it can be used in other keyring tests.
 * For the moment, we are just moving relevant pieces here and exposing the innards
 * entirely through the header file so as not to make breaking changes the multi
 * keyring tests. We may eventually want to build a cleaner interface to this code.
 */

struct test_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_byte_buf generated_data_key_to_return;
    struct aws_byte_buf decrypted_data_key_to_return;
    int ret;
    bool skip_output;
    bool on_encrypt_called;
    bool on_decrypt_called;
    bool destroy_called;
};

extern const struct aws_cryptosdk_keyring_vt test_keyring_vt;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Decrypts using a specific keyring and saves result in result_output
 * Note: result_output needs to be cleaned using aws_byte_buf_clean_up
*/
int test_keyring_datakey_decrypt(struct aws_byte_buf *result_output,
                                 struct aws_cryptosdk_keyring *keyring,
                                 struct aws_cryptosdk_edk *edk,
                                 struct aws_hash_table *enc_context,
                                 enum aws_cryptosdk_alg_id alg);

/**
 * Encrypts using a specific keyring and saves result in result_output
 * Note: result_output needs to be cleaned using aws_cryptosdk_edk_list_clean_up
*/
int test_keyring_datakey_encrypt(struct aws_array_list *result_output,
                                 struct aws_cryptosdk_keyring *keyring,
                                 const char *plain_text,
                                 struct aws_hash_table *enc_context,
                                 enum aws_cryptosdk_alg_id alg);

/**
 * Decrypts content of edk and then compares with expected_plain_text
 * @return 0 on success when content of decryption is equal with expected_plain_text
 */
int test_keyring_datakey_decrypt_and_compare_with_pt(const struct aws_byte_buf *expected_plain_text,
                                                     struct aws_cryptosdk_keyring *keyring,
                                                     struct aws_cryptosdk_edk *edk,
                                                     struct aws_hash_table *enc_context,
                                                     enum aws_cryptosdk_alg_id alg);

/**
 * Decrypts content of edk and then compares with expected_plain_text
 * @return 0 on success when content of decryption is equal with expected_plain_text
 */
int test_keyring_datakey_decrypt_and_compare_with_c_str_pt(const char *expected_plain_text,
                                                     struct aws_cryptosdk_keyring *keyring,
                                                     struct aws_cryptosdk_edk *edk,
                                                     struct aws_hash_table *enc_context,
                                                     enum aws_cryptosdk_alg_id alg);

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_TESTS_LIB_TEST_KEYRING_H

