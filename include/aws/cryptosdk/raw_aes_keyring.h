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
 * A keyring which does local AES-GCM encryption and decryption of data keys using
 * the bytes in the array provided as the wrapping key.
 *
 * Key namespace, name, and raw key bytes provided by the caller are copied into
 * the state of the KR, so those arrays do not need to be maintained while using the KR.
 * For maximum security, the caller should zero out the array of raw key bytes after
 * creating this object.
 *
 * The encryption context which is passed to this KR on encrypt and decrypt calls is
 * used as additional authenticated data (AAD) in the AES-GCM encryption of the data keys.
 * This means that the same encryption context must be present for both encryption and
 * decryption.
 *
 * Set your own namespace and name for the wrapping key you use, for bookkeeping purposes.
 * A raw AES keyring which attempts to decrypt data previously encrypted by another raw
 * AES keyring must specify the same name and namespace.
 *
 * Note: when this keyring is used, it generates a trace that includes copies of the
 * namespace and name strings for each call. If you generate either or both of the
 * namespace and name strings using the AWS_STATIC_STRING_FROM_LITERAL macro, all
 * copies of these strings will be optimized out.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_keyring * aws_cryptosdk_raw_aes_keyring_new(struct aws_allocator *alloc,
                                                                 const struct aws_string *key_namespace,
                                                                 const struct aws_string *key_name,
                                                                 const uint8_t *key_bytes,
                                                                 enum aws_cryptosdk_aes_key_len key_len);

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_RAW_AES_KEYRING_H
