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
 * Manager (CMM). A Keyring must have already been instantiated and a pointer
 * to it passed in. This CMM implements all of the CMM virtual functions.
 *
 * On each call to Generate Encryption Materials, it makes a call to the
 * keyring's On Encrypt function to generate and encrypt a data key. If an
 * algorithm suite that does not include signing is used, this is the only
 * thing that the Generate Encryption Materials does. If an algorithm suite
 * that does include signing is used, then the call additionally begins the
 * calculation of the trailing signature, which will be completed by the
 * session.
 *
 * On each call to Decrypt Materials, it passes the full list of EDKs to the
 * keyring and asks it to find one to decrypt, via the keyring's On Decrypt
 * function. If an algorithm suite that does not include signing is used, this
 * is the only thing that the Decrypt Materials call does. If an algorithm
 * suite that does include signing is used, then the call additionally begins
 * the verification of the trailing signature, which will be completed by the
 * session.
 *
 * If a CMM that delegates to the default CMM selects an algorithm suite, that
 * algorithm suite will be used. Otherwise, the default CMM will select a default
 * algorithm suite. This is initially ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
 * or ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, depending on the
 * session's configured key commitment policy, but can be overridden using
 * aws_cryptosdk_default_cmm_set_alg_id.
 *
 * On success allocates a CMM and returns a pointer to it. Be sure to call
 * aws_cryptosdk_cmm_release when you are done using the pointer so that the
 * memory is properly deallocated.
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

AWS_CRYPTOSDK_API
bool aws_cryptosdk_default_cmm_is_valid(const struct aws_cryptosdk_cmm *cmm);

#ifdef __cplusplus
}
#endif

#endif  // AWS_CRYPTOSDK_DEFAULT_CMM_H
