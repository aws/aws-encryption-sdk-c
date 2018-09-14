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

#ifndef AWS_CRYPTOSDK_DEFAULT_CMM_H
#define AWS_CRYPTOSDK_DEFAULT_CMM_H

#include <aws/cryptosdk/materials.h>

/**
 * Instantiate the default (non-caching) implementation of the Crypto Materials
 * Manager (CMM). A Keyring (KR) must have already been instantiated
 * and a pointer to it passed in. This CMM maintains no state of its own other
 * than pointers to the KR and allocator. It implements all of the CMM virtual
 * functions.
 *
 * On each attempt to generate encryption materials, it asks the KR to generate a
 * data key.
 *
 * On each attempt to decrypt materials, it passes the full list of EDKs to the KR
 * and asks it to find one to decrypt.
 *
 * TODO: Trailing signature keys are not implemented yet in this CMM.
 *
 * On success allocates a CMM and returns its address. Be sure to deallocate it later
 * by calling aws_cryptosdk_cmm_destroy on the CMM pointer returned by this function.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
struct aws_cryptosdk_cmm * aws_cryptosdk_default_cmm_new(struct aws_allocator * alloc,
                                                         struct aws_cryptosdk_keyring * kr);

#endif // AWS_CRYPTOSDK_DEFAULT_CMM_H
