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

#ifndef AWS_CRYPTOSDK_TESTS_UNIT_ZERO_MKP_H
#define AWS_CRYPTOSDK_TESTS_UNIT_ZERO_MKP_H

#include <aws/cryptosdk/materials.h>

/**
 * A degenerate MKP/MK which always returns an all zero data key, just
 * for testing the CMM/MKP/MK infrastructure.
 *
 * The EDK it generates has all byte buffer lengths and allocators set to
 * zero, so that data encrypted with it can be serialized correctly and
 * clean up functions work properly.
 *
 * On attempts to decrypt, it checks whether one of the provided EDKs has
 * zero length, and if so returns the all zero data key.
 */
struct aws_cryptosdk_mkp * aws_cryptosdk_zero_mkp_new();

#endif // AWS_CRYPTOSDK_TESTS_UNIT_ZERO_MKP_H
