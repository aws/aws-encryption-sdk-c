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
 * The default CMM will always encrypt using the same algorithm suite. By default,
 * this is AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE, but can be overridden using
 * aws_cryptosdk_default_cmm_set_alg_id. If the default CMM is wrapped by another CMM,
 * the outer CMM must either not set the requested algorithm ID, or it must set the
 * same requested algorithm ID as the default CMM.
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

/**
 * Selects the algorithm suite ID to use for encryption. If not called, a reasonable
 * default will be selected.
 * Raises AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT if the algorithm suite ID is unknown.
 */
int aws_cryptosdk_default_cmm_set_alg_id(struct aws_cryptosdk_cmm *cmm, enum aws_cryptosdk_alg_id alg_id);

#endif // AWS_CRYPTOSDK_DEFAULT_CMM_H
