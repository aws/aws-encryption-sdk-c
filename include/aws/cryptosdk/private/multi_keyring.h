/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#ifndef AWS_CRYPTOSDK_PRIVATE_MULTI_KEYRING_H
#define AWS_CRYPTOSDK_PRIVATE_MULTI_KEYRING_H

#include <aws/cryptosdk/multi_keyring.h>

struct multi_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_allocator *alloc;
    struct aws_cryptosdk_keyring *generator;
    struct aws_array_list children;  // list of (struct aws_cryptosdk_keyring *)
};

#endif  // AWS_CRYPTOSDK_PRIVATE_MULTI_KEYRING_H
