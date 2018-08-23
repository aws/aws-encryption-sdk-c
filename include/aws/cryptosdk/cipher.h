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

#ifndef AWS_CRYPTOSDK_CIPHER_H
#define AWS_CRYPTOSDK_CIPHER_H

#include <aws/common/string.h>
#include <aws/cryptosdk/header.h>

enum aws_cryptosdk_aes_key_len {
    AWS_CRYPTOSDK_AES_128 = 128/8,
    AWS_CRYPTOSDK_AES_192 = 192/8,
    AWS_CRYPTOSDK_AES_256 = 256/8
};

struct aws_cryptosdk_alg_properties {
    const char *md_name, *cipher_name, *alg_name;

    /**
     * Pointer to a structure containing crypto-backend-specific
     * information. This is a forward-declared structure to keep it
     * opaque to backend-independent code
     */
    const struct aws_cryptosdk_alg_impl *impl;

    size_t data_key_len, content_key_len, iv_len, tag_len, signature_len;

    enum aws_cryptosdk_alg_id alg_id;
};

const struct aws_cryptosdk_alg_properties *aws_cryptosdk_alg_props(enum aws_cryptosdk_alg_id alg_id);

#endif // AWS_CRYPTOSDK_CIPHER_H
