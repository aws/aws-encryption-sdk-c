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

#ifndef AWS_CRYPTOSDK_TESTS_LIB_ZERO_KEYRING_H
#define AWS_CRYPTOSDK_TESTS_LIB_ZERO_KEYRING_H

#include <aws/cryptosdk/materials.h>
#include "testutil.h"

/**
 * A degenerate Keyring (KR) which always returns an all zero data key, just
 * for testing the CMM and KR infrastructure.
 *
 * The EDK it generates has the string "null" in every field.
 *
 * On attempts to decrypt, it checks whether one of the provided EDKs has
 * zero length, and if so returns the all zero data key.
 */
TESTLIB_API
struct aws_cryptosdk_keyring *aws_cryptosdk_zero_keyring_new(struct aws_allocator *alloc);

/**
 * Convenience for testing: sets an EDK to "null" in every field.
 * Points to static memory, so it does not need to be deallocated.
 */
TESTLIB_API
void aws_cryptosdk_literally_null_edk(struct aws_cryptosdk_edk *edk);

#endif  // AWS_CRYPTOSDK_TESTS_LIB_ZERO_KEYRING_H
