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

#include <aws/cryptosdk/materials.h>

/**
 * Creates a new multi-keyring. This keyring allows you to combine keyrings into
 * a single keyring. When used for encryption, the resulting document can be 
 * decrypted by any of the included keyrings. When used for decryption, the multi-
 * keyring will attempt to decrypt using each of the included keyrings.
 *
 * A generator keyring is needed for calls to generate data key, but not for calls
 * to encrypt data key and decrypt data key. It can be set as the second argument
 * of this function, or caller may make that argument NULL to not set a generator.
 * It can later be set by calling aws_cryptosdk_multi_keyring_set_generator.
 *
 * Initially the multi keyring has no included keyrings. In this state, generate,
 * encrypt, and decrypt calls will trivially succeed without actually generating,
 * encrypting, or decrypting data keys. Call aws_cryptosdk_multi_keyring_add
 * to add other keyrings to a multi-keyring.
 *
 * Destroying this keyring will NOT destroy the keyrings that were added to it. Be
 * sure to call the destructors on those keyrings too in order to avoid memory leaks.
 *
 * On generate data key calls, this will generate the data key with the generator
 * keyring, which generally also puts an EDK on the list. It will then attempt to
 * encrypt the data key with each child keyring that was added. On an error from
 * the generator or any child keyring, AWS_OP_ERR will be returned, and no data key
 * or EDKs will be added to the encryption materials. The generator or child keyring
 * that had the error is expected to set the error code.
 *
 * Encrypt data key calls are similar, except that encrypt is called on every child
 * keyring, and the generator, if one is set.
 *
 * Decrypt data key will attempt to decrypt one of the EDKs with each child keyring,
 * and the generator (if one is set) until it succeeds. Errors from child keyrings
 * will not stop it from proceeding to others. If it succeeds in decrypting an EDK,
 * it will return AWS_OP_SUCCESS, even if one or more of the child keyrings failed.
 * If it does not succeed in decrypting an EDK, it will return AWS_OP_SUCCESS if
 * there were no errors, and AWS_OP_ERR if there were errors. As with all decrypt
 * data key calls, check decryption materials unencrypted_data_key.buffer to see
 * whether an EDK was decrypted.
 */
struct aws_cryptosdk_keyring *aws_cryptosdk_multi_keyring_new(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_keyring *generator);

/**
 * Sets the generator keyring of this multi-keyring. This will be the keyring
 * that will be called to generate data keys, which the child keyrings will then
 * encrypt. On calls to encrypt or decrypt a data key, the generator keyring
 * will just be treated as another child keyring, if it is set. Calls to
 * generate a data key will fail if the generator is not set, but calls to
 * encrypt and decrypt data key are allowed.
 *
 * The generator of a multi-keyring cannot be changed. Multiple calls to this
 * function, or calling it after setting the generator upon construction, will
 * fail.
 */
int aws_cryptosdk_multi_keyring_set_generator(
    struct aws_cryptosdk_keyring *multi,
    struct aws_cryptosdk_keyring *generator);

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
int aws_cryptosdk_multi_keyring_add(struct aws_cryptosdk_keyring *multi,
                                    struct aws_cryptosdk_keyring *child);

#endif // AWS_CRYPTOSDK_MULTI_KEYRING_H
