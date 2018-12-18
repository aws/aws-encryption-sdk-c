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
#ifndef AWS_CRYPTOSDK_RAW_RSA_KEYRING_H
#define AWS_CRYPTOSDK_RAW_RSA_KEYRING_H

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/materials.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup raw_keyring
 * A keyring which does local RSA encryption and decryption of data keys using
 * the RSA keys provided as a null terminated C-string in PEM format.
 *
 * Here, 'rsa_public_key_pem' is a null terminated C-string containing the public
 * key in PEM format and 'rsa_private_key_pem' is a null terminated C-string
 * containing the private key in PEM format. Note that either argument may be set
 * to NULL. Encryption is possible only when a public key is provided, and
 * decryption is possible only when a private key is provided.
 *
 * Key namespace, name, RSA private key and RSA public key provided by the caller
 * are copied into the state of the keyring, so those arrays do not need to be
 * maintained while using the keyring. For maximum security, the caller should
 * zero out the array of 'rsa_private_key_pem' after creating this object.
 *
 * Set your own namespace and name for the wrapping (RSA) key you use, for
 * bookkeeping purposes. A raw RSA keyring which attempts to decrypt data
 * previously encrypted by another raw RSA keyring must specify the same name
 * and namespace.
 *
 * Note: when this keyring is used, it generates a trace that includes copies of
 * the namespace and name strings for each call. If you generate either or both of
 * the namespace and name strings using the AWS_STATIC_STRING_FROM_LITERAL macro,
 * all copies of these strings will be optimized out.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_keyring *aws_cryptosdk_raw_rsa_keyring_new(
    struct aws_allocator *alloc,
    const struct aws_string *key_namespace,
    const struct aws_string *key_name,
    const char *rsa_private_key_pem,
    const char *rsa_public_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

#ifdef __cplusplus
}
#endif

#endif  // AWS_CRYPTOSDK_RAW_RSA_KEYRING_H
