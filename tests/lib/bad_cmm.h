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

#include <aws/cryptosdk/materials.h>

/**
 * Returns a pointer to the singleton zero size CMM. This is a CMM with virtual
 * functions implemented but which has its size set to zero, which should prevent
 * the virtual functions from ever being called.
 */
struct aws_cryptosdk_cmm * aws_cryptosdk_zero_size_cmm_new();

/**
 * Returns a pointer to the singleton null CMM. This is a CMM with size field set
 * correctly, but with all null pointers in place of its virtual function pointers.
 * It is for testing that the VF calling code never attempts to call function
 * pointers set to null.
 */
struct aws_cryptosdk_cmm * aws_cryptosdk_null_cmm_new();

/**
 * Convenience function for tests. Equivalent to calling aws_cryptosdk_cmm_destroy(cmm)
 * and also provides a return value of AWS_OP_ERR just because our TEST_ASSERT_ERROR
 * macro looks for that when checking the error code.
 */
int aws_cryptosdk_cmm_destroy_with_failed_return_value(struct aws_cryptosdk_cmm * cmm);

#endif // AWS_CRYPTOSDK_TESTS_LIB_BAD_CMM_H
