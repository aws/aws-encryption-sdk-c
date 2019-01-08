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
#ifndef AWS_CRYPTOSDK_MULTI_KEYRING_H
#define AWS_CRYPTOSDK_MULTI_KEYRING_H

#include <aws/cryptosdk/exports.h>
#include <aws/cryptosdk/materials.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup cmm_kr_highlevel
 * @{
 */

/**
 * Creates a new multi-keyring. This keyring allows you to combine keyrings into
 * a single keyring. When used for encryption, the resulting document can be
 * decrypted by any of the included keyrings. When used for decryption, the multi-
 * keyring will attempt to decrypt using each of the included keyrings.
 *
 * The second argument provided to the constructor is this multi-keyring's
 * generator keyring, which is the first keyring it will call on encryption and
 * decryption attempts, when it is set.
 *
 * You may create a multi-keyring with no generator by setting the argument to NULL.
 * If a generator is not set, the multi-keyring may be used for decryption or for
 * encryption after another keyring has already generated a data key, (for example,
 * as a child keyring of another multi-keyring.) However, a multi-keyring with no
 * generator is not usable for encryption on its own.
 *
 * Calling the multi-keyring's On Encrypt method without a provided unencrypted
 * data key will cause it to do the following:
 *
 * (1) Call the generator's On Encrypt method.
 * (2) Verify that an unencrypted data key has been generated.
 * (3) Call the child keyrings' On Encrypt methods.
 * (4) If all previous calls have succeeded, return the unencrypted data key
 *     and append all EDKs to the list provided by the caller.
 *
 * If the generator is not set, or if it fails to generate an unencrypted
 * data key, or if any of the delegated calls fail, the multi-keyring's On
 * Encrypt call will fail without modifying its arguments. In the first two
 * cases it will set the error code AWS_CRYPTOSDK_ERR_BAD_STATE. In the case of a
 * delegated call failing, it will not set an error code, so as not to overwrite
 * the error code of the failing keyring.
 *
 * If the multi-keyring's On Encrypt method is called WITH a provided unencrypted
 * data key, it will skip directly to step (3) above, meaning that the generator
 * will never be called.
 *
 * The multi-keyring's On Decrypt call will attempt to decrypt an EDK with each
 * child keyring and the generator (if one is set) until it succeeds. Errors from
 * any keyrings will not stop it from proceeding to the rest. If it succeeds in
 * decrypting an EDK, it will return AWS_OP_SUCCESS, even if one or more of the
 * keyrings failed. If it does not succeed in decrypting an EDK, it will return
 * AWS_OP_SUCCESS if there were no errors, and AWS_OP_ERR if there were errors.
 * As with all On Decrypt calls, check unencrypted_data_key.buffer to see
 * whether an EDK was decrypted.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_keyring *aws_cryptosdk_multi_keyring_new(
    struct aws_allocator *alloc, struct aws_cryptosdk_keyring *generator);

/**
 * Adds a new child keyring to this multi-keyring. Child keyrings are only used
 * to encrypt or decrypt a data key, not to generate new data keys. Do not add
 * the generator keyring as a child keyring. This will result in generated data
 * keys getting encrypted twice by that keyring, which is useless.
 *
 * This operation is not threadsafe. If this is called at the same time as the
 * multi-keyring is used for encrypt or decrypt, it results in undefined behavior.
 *
 * It is not possible to remove a keyring from the multi-keyring at this time.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_multi_keyring_add_child(struct aws_cryptosdk_keyring *multi, struct aws_cryptosdk_keyring *child);

/** @} */  // doxygen group cmm_kr_highlevel

#ifdef __cplusplus
}
#endif

#endif  // AWS_CRYPTOSDK_MULTI_KEYRING_H
