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

#ifndef AWS_CRYPTOSDK_TESTS_UNIT_ZERO_MK_H
#define AWS_CRYPTOSDK_TESTS_UNIT_ZERO_MK_H

#include <aws/cryptosdk/materials.h>

/**
 * A degenerate MK which always returns an all zero data key, just
 * for testing the CMM/MKP/MK infrastructure.
 *
 * The EDK it generates has the string "null" in every field.
 *
 * On attempts to decrypt, it checks whether one of the provided EDKs has
 * zero length, and if so returns the all zero data key.
 */
struct aws_cryptosdk_mk * aws_cryptosdk_zero_mk_new();

/**
 * Convenience for testing: sets an EDK to "null" in every field.
 * Points to static memory, so it does not need to be deallocated.
 */
void aws_cryptosdk_literally_null_edk(struct aws_cryptosdk_edk * edk);

#endif // AWS_CRYPTOSDK_TESTS_UNIT_ZERO_MK_H
