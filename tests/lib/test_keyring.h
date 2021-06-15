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
#include "testutil.h"

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
    bool on_encrypt_ignore_existing_data_key;
};

TESTLIB_API
extern const struct aws_cryptosdk_keyring_vt test_keyring_vt;

#endif  // AWS_CRYPTOSDK_TESTS_LIB_TEST_KEYRING_H
