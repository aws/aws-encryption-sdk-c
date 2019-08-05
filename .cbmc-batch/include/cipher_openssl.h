/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef CIPHER_OPENSSL_H
#define CIPHER_OPENSSL_H

#include <aws/cryptosdk/private/cipher.h>

/* The definitions in this file are directly copied from cipher_openssl.c, in order to make the internals of the data
 * structures accessible from the CBMC proof harness. */

struct aws_cryptosdk_sig_ctx {
    struct aws_allocator *alloc;
    const struct aws_cryptosdk_alg_properties *props;
    EC_KEY *keypair;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    bool is_sign;
};

struct aws_cryptosdk_md_context {
    struct aws_allocator *alloc;
    EVP_MD_CTX *evp_md_ctx;
};

#endif
