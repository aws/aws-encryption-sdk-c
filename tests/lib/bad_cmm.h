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

#ifndef AWS_CRYPTOSDK_TESTS_LIB_BAD_CMM_H
#define AWS_CRYPTOSDK_TESTS_LIB_BAD_CMM_H

#include "testutil.h"
#include <aws/cryptosdk/materials.h>

/**
 * Returns a zero size CMM. This is a CMM with virtual functions implemented but which
 * has its size set to zero, which should prevent the virtual functions from ever being called.
 * Because the destroy function does not work, we return this by-value and rely on stack cleanup
 * to free the memory associated with this CMM.
 */
TESTLIB_API
struct aws_cryptosdk_cmm aws_cryptosdk_zero_size_cmm();

/**
 * Returns a zero size CMM. This is a CMM with virtual functions implemented but which
 * has all NULL vtable pointers, to verify that the VF code does not call function pointers
 * set to null.
 *
 * Because the destroy function does not work, we return this by-value and rely on stack cleanup
 * to free the memory associated with this CMM.
 */
TESTLIB_API
struct aws_cryptosdk_cmm aws_cryptosdk_null_cmm();

/**
 * Convenience function for tests. Equivalent to calling aws_cryptosdk_cmm_destroy(cmm)
 * and also provides a return value of AWS_OP_ERR just because our TEST_ASSERT_ERROR
 * macro looks for that when checking the error code.
 */
TESTLIB_API
int aws_cryptosdk_cmm_release_with_failed_return_value(struct aws_cryptosdk_cmm * cmm);

#endif // AWS_CRYPTOSDK_TESTS_LIB_BAD_CMM_H
