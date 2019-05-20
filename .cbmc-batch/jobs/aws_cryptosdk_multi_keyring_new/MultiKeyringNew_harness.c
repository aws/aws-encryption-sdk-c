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

#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/multi_keyring.h>
#include "proof_allocators.h"

// This is a memory safety proof for aws_cryptosdk_multi_keyring() defined in
// https://github.com/aws/aws-encryption-sdk-c/blob/master/source/multi_keyring.c
void harness() {
    struct aws_allocator *alloc = can_fail_allocator();
    struct aws_cryptosdk_keyring generator;
    aws_cryptosdk_keyring_base_init(&generator, NULL);
    struct aws_cryptosdk_keyring *result = aws_cryptosdk_multi_keyring_new(alloc, &generator);
}
