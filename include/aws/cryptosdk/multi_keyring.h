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
 * Calling the multi-keyring's On Encrypt method does the following:
 *
 * (1) Call the generator's On Encrypt method, if a generator has been set.
 *     If the generator's On Encrypt method fails, the multi-keyring's On Encrypt
 *     fails immediately, and the error code will be set by the generator keyring.
 *
 * (2) Verify that an unencrypted data key has been generated, setting an error
 *     code of AWS_CRYPTOSDK_ERR_BAD_STATE and failing if it has not.
 *
 * (3) Call the child keyrings' On Encrypt methods, producing a list of
 *     EDKs that are all encrypted versions of the data key verified in step (2).
 *     If any of the child keyring's On Encrypt methods fail, the multi-keyring's
 *     On Encrypt method will fail immediately, and the error code will be set
 *     by the failing child keyring.
 *
 * (4) If all previous calls have succeeded, return the unencrypted data key
 *     and append all EDKs to the list provided by the caller.
 *
 * The multi-keyring's On Decrypt call will attempt to decrypt an EDK with the
 * generator (if one is set) and then each child keyring until it succeeds. Errors
 * from any keyrings will not stop it from proceeding to the rest. If it succeeds
 * in decrypting an EDK, it will return AWS_OP_SUCCESS, even if one or more of the
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

/**
 * Constant time check of data-structure invariants for struct multi_keyring.
 */
AWS_CRYPTOSDK_API
bool aws_cryptosdk_multi_keyring_is_valid(struct aws_cryptosdk_keyring *multi);

/** @} */  // doxygen group cmm_kr_highlevel

#ifdef __cplusplus
}
#endif

#endif  // AWS_CRYPTOSDK_MULTI_KEYRING_H
