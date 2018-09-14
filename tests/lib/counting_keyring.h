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

#ifndef AWS_CRYPTOSDK_TESTS_LIB_COUNTING_KEYRING_H
#define AWS_CRYPTOSDK_TESTS_LIB_COUNTING_KEYRING_H

#include <aws/cryptosdk/materials.h>

/**
 * Returns a Keyring for testing. This Keyring uses/"decrypts" data keys
 * identified with a particular test pattern, and for this test pattern,
 * assigns a data key where the first byte is zero, the second byte is 0x01,
 * and so on.
 *
 * The test pattern used for generated data key (or decrypted data keys) has
 * "test_counting" as the provider ID, "test_counting_prov_info" as the
 * provider info, and 0x4041424344 as the encrypted data key field; EDKs not
 * conforming to this will not be considered decryptable using this Keyring.
 */
struct aws_cryptosdk_keyring *aws_cryptosdk_counting_keyring();

#endif /* AWS_CRYPTOSDK_TESTS_LIB_COUNTING_KEYRING_H */
