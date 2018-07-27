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

#ifndef AWS_CRYPTOSDK_MULTI_MKP_H
#define AWS_CRYPTOSDK_MULTI_MKP_H

#include <aws/cryptosdk/materials.h>

/**
 * Creates a new multi-master-key-provider. This provider allows you to combine multiple
 * MKPs into a single MKP. When used for encryption, the resulting document can be decrypted
 * by any of the included MKPs; when used for decryption, the multi MKP will attempt to
 * decrypt using each of the registered child MKPs.
 * 
 * Initially the multi MKP has no child MKPs, and will fail if used directly for an encrypt
 * or decrypt operation. Call aws_cryptosdk_multi_mkp_add to add child MKPs.
 */
struct aws_cryptosdk_mkp *aws_cryptosdk_multi_mkp_new(struct aws_allocator *alloc);

/**
 * Adds a new child MKP to this multi MKP. This operation is not threadsafe; if this is called
 * at the same time as the multi-mkp is used for encrypt or decrypt, it results in undefined
 * behavior.
 * 
 * Creating a cycle of multi-mkps will result in infinite recursion and should be avoided.
 * 
 * It is not possible to remove a MKP from the multi-MKP at this time.
 * 
 * Arguments:
 *   multi_mkp       - The multi-mkp to add a child MKP to
 *   mkp             - The child MKP to add
 */
int aws_cryptosdk_multi_mkp_add(
    struct aws_cryptosdk_mkp *multi_mkp,
    struct aws_cryptosdk_mkp *mkp
);

#endif // AWS_CRYPTOSDK_MULTI_MKP_H
