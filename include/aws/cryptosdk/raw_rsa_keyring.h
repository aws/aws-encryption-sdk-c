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

/**
 * A Keyring (KR) which does local RSA encryption and decryption of data keys using
 * the RSA keys provided as a null terminated C-string in PEM format.
 *
 * Here, 'rsa_public_key_pem' is a null terminated C-string containing the public key 
 * in PEM format and 'rsa_private_key_pem' is a null terminated C-string containing the
 * private key in PEM format. Note that either argument may be set to NULL. Encryption 
 * is possible only when a public key is provided, and decryption is possible only when 
 * a private key is provided. 
 * 
 * Key name, name space, RSA private key and RSA public key provided by the
 * caller are copied into the state of the KR, so those arrays do not need to be
 * maintained while using the KR. For maximum security, the caller should zero out the
 * arrays of 'rsa_private_key_pem' after creating this object.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_keyring *aws_cryptosdk_raw_rsa_keyring_new(
    struct aws_allocator *alloc,
    const uint8_t *key_name,
    size_t key_name_len,
    const uint8_t *name_space,
    size_t name_space_len,
    const char *rsa_private_key_pem,
    const char *rsa_public_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

#endif  // AWS_CRYPTOSDK_RAW_RSA_KEYRING_H
