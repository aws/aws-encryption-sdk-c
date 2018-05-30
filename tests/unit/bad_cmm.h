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

#ifndef AWS_CRYPTOSDK_TESTS_UNIT_BAD_CMM_H
#define AWS_CRYPTOSDK_TESTS_UNIT_BAD_CMM_H

#include <stdbool.h>
#include <aws/cryptosdk/materials.h>

/**
 * Returns a pointer to the singleton zero size CMM.
 * This is a CMM with virtual functions implemented but
 * which has its size set to zero, which should prevent
 * the virtual functions from ever being called.
 */
struct aws_cryptosdk_cmm * aws_cryptosdk_zero_size_cmm_new();

/**
 * Returns true if the zero size CMM's destroy virtual
 * function was called. Should always return false.
 */
bool zero_size_cmm_did_destroy_vf_run();

/**
 * Returns a pointer to the singleton null CMM.
 * This is a CMM with size field set correctly,
 * but with all null pointers in place of its
 * virtual function pointers.
 */
struct aws_cryptosdk_cmm * aws_cryptosdk_null_cmm_new();

#endif // AWS_CRYPTOSDK_TESTS_UNIT_BAD_CMM_H
