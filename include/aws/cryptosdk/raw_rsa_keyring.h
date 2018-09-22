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
 * the RSA key provided as a string in PEM format.
 *
 * Here, 'rsa_key_public_pem' is a string containing the public key in PEM format and
 * 'rsa_key_private_pem' is a string containing the private key in PEM format.
 * Note both these arguments are expected to be a null terminated C-string for determining
 * its length. 
 * 
 * Master key ID, provider ID, RSA private key and RSA public key provided by the
 * caller are copied into the state of the KR, so those arrays do not need to be
 * maintained while using the KR. For maximum security, the caller should zero out the
 * arrays of 'rsa_key_private_pem' and 'rsa_key_public_pem' after creating this object.
 *
 * On failure returns NULL and sets an internal AWS error code.
 */
struct aws_cryptosdk_keyring *aws_cryptosdk_raw_rsa_keyring_new(
    struct aws_allocator *alloc,
    const uint8_t *master_key_id,
    size_t master_key_id_len,
    const uint8_t *provider_id,
    size_t provider_id_len,
    const char *rsa_key_private_pem,
    const char *rsa_key_public_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

#endif  // AWS_CRYPTOSDK_RAW_RSA_KEYRING_H
