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

#include <aws/cryptosdk/exports.h>
#include <aws/cryptosdk/materials.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup cmm_kr_highlevel
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
 * If a CMM that delegates to the default CMM selects an algorithm suite, that algorithm
 * suite will be used. Otherwise, the default CMM will select a default algorithm suite.
 * This is initially ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, but can be overridden using
 * aws_cryptosdk_default_cmm_set_alg_id.
 *
 * On success allocates a CMM and returns its address. Be sure to deallocate it later
 * by calling aws_cryptosdk_cmm_destroy on the CMM pointer returned by this function.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_cmm *aws_cryptosdk_default_cmm_new(struct aws_allocator *alloc, struct aws_cryptosdk_keyring *kr);

/**
 * @ingroup cmm_kr_highlevel
 * Selects the algorithm suite ID to use for encryption. If not called, a reasonable
 * default will be selected.
 * Raises AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT if the algorithm suite ID is unknown.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_default_cmm_set_alg_id(struct aws_cryptosdk_cmm *cmm, enum aws_cryptosdk_alg_id alg_id);

#ifdef __cplusplus
}
#endif

#endif  // AWS_CRYPTOSDK_DEFAULT_CMM_H
