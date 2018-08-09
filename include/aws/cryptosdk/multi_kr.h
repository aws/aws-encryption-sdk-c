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
#ifndef AWS_CRYPTOSDK_MULTI_KR_H
#define AWS_CRYPTOSDK_MULTI_KR_H

#include <aws/cryptosdk/materials.h>

/**
 * Creates a new multi-keyring. This keyring allows you to combine keyrings into
 * a single keyring. When used for encryption, the resulting document can be 
 * decrypted by any of the included keyrings; when used for decryption, the multi-
 * keyring will attempt to decrypt using each of the included keyrings.
 *
 * Initially the multi keyring has no included keyrings, and will fail if used
 * directly for an encrypt or decrypt operation. Call aws_cryptosdk_multi_mkp_add
 * to add other keyrings to a multi-keyring.
 */
struct aws_cryptosdk_kr * aws_cryptosdk_multi_kr_new(struct aws_allocator * alloc);

/**
 * Adds a new keyring to this multi-keyring. This operation is not threadsafe.
 * If this is called at the same time as the multi-mkp is used for encrypt or
 * decrypt, it results in undefined behavior.
 *
 * It is not possible to remove a MKP from the multi-MKP at this time.
 */
int aws_cryptosdk_multi_kr_add(struct aws_cryptosdk_kr * multi_kr,
                               struct aws_cryptosdk_kr * kr_to_add);

#endif // AWS_CRYPTOSDK_MULTI_KR_H
