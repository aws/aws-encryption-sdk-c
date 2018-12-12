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
#ifndef AWS_CRYPTOSDK_RAW_AES_KEYRING_H
#define AWS_CRYPTOSDK_RAW_AES_KEYRING_H

#include <aws/cryptosdk/exports.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/cipher.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup raw_keyring Keyrings using local (raw) keys
 * @{
 */

/**
 * Builds a keyring which does local AES-GCM encryption and decryption of data keys using
 * the bytes in the array provided as the AES key.
 *
 * Master key ID, provider ID and raw key bytes provided by the caller are copied into
 * the state of the KR, so those arrays do not need to be maintained while using the KR.
 * For maximum security, the caller should zero out the array of raw key bytes after
 * creating this object.
 *
 * The encryption context which is passed to this KR on encrypt and decrypt calls is
 * used as additional authenticated data (AAD) in the AES-GCM encryption of the data keys.
 * This means that the same encryption context must be present for both encryption and
 * decryption. The master key ID and provider ID are solely used to determine which master
 * key to use, so if they do not match, this KR will not find the encrypted data key to
 * decrypt. In other words, a raw AES KR which attempts to decrypt data previously
 * encrypted by another raw AES KR must have the same master key ID and provider ID.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_keyring * aws_cryptosdk_raw_aes_keyring_new(struct aws_allocator * alloc,
                                                                 const uint8_t * master_key_id,
                                                                 size_t master_key_id_len,
                                                                 const uint8_t * provider_id,
                                                                 size_t provider_id_len,
                                                                 const uint8_t * raw_key_bytes,
                                                                 enum aws_cryptosdk_aes_key_len key_len);

/** @} */ // doxygen group raw_keyring

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_RAW_AES_KEYRING_H
