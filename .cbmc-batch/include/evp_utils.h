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

#ifndef EVP_UTILS_H
#define EVP_UTILS_H

#include <openssl/evp.h>

bool evp_pkey_is_valid(EVP_PKEY *pkey);

EVP_PKEY *evp_pkey_nondet_alloc();

int evp_pkey_get_reference_count(EVP_PKEY *pkey);

void evp_pkey_set0_ec_key(EVP_PKEY *pkey, EC_KEY *ec);

void evp_pkey_unconditional_free(EVP_PKEY *pkey);

bool evp_md_ctx_is_valid(EVP_MD_CTX *ctx);

EVP_MD_CTX *evp_md_ctx_nondet_alloc();

bool evp_md_ctx_is_initialized(EVP_MD_CTX *ctx);

size_t evp_md_ctx_get_digest_size(EVP_MD_CTX *ctx);

EVP_PKEY *evp_md_ctx_get0_evp_pkey(EVP_MD_CTX *ctx);

void evp_md_ctx_set0_evp_pkey(EVP_MD_CTX *ctx, EVP_PKEY *pkey);

void evp_md_ctx_shallow_free(EVP_MD_CTX *ctx);

#endif
