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

struct aws_cryptosdk_keyring *aws_cryptosdk_raw_rsa_keyring_new(
    struct aws_allocator *alloc,
    const uint8_t *master_key_id,
    size_t master_key_id_len,
    const uint8_t *provider_id,
    size_t provider_id_len,
    const uint8_t *raw_key_bytes,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

#endif  // AWS_CRYPTOSDK_RAW_RSA_KEYRING_H
