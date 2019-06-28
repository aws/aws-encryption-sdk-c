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

#include <openssl/evp.h>

#include <make_common_data_structures.h>
#include <proof_helpers/nondet.h>

void EVP_PKEY_free(EVP_PKEY *pkey) {
    assert(pkey != NULL);
}

struct evp_md_ctx_st {
    bool is_initialized;
};

bool evp_md_ctx_is_initialized(EVP_MD_CTX *ctx) {
    return ctx && ctx->is_initialized;
}

EVP_MD_CTX *EVP_MD_CTX_new() {
    EVP_MD_CTX *ctx = can_fail_malloc(sizeof(EVP_MD_CTX));

    // OpenSSL implementation uses OPENSSL_zalloc, which according to the documentation returns NULL on error.
    // Therefore, cannot guarantee that pointer is not NULL.
    return ctx;
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    // OpenSSL implementation is a no-op if ctx is NULL
    if (ctx) {
        free(ctx);
    }
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
    assert(ctx != NULL);
    assert(type != NULL);
    // OpenSSL documentation allows impl to be NULL

    ctx->is_initialized = nondet_bool();

    // Unclear if we can assume all fields of ctx are non-NULL if ctx is initialized

    return ctx->is_initialized;  // OpenSSL documentation: 1 for success, 0 for failure
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
    assert(ctx != NULL);  // OpenSSL implementation dereferences ctx
    assert(ctx->is_initialized);
    assert(d != NULL);  // unclear if this is necessary or if OpenSSL tests for it
    assert(AWS_MEM_IS_READABLE(d, cnt));

    return nondet_bool();  // OpenSSL documentation: 1 for success, 0 for failure
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) {
    assert(ctx != NULL);  // OpenSSL implementation dereferences ctx
    assert(ctx->is_initialized);
    // ctx->digest is allowed to be NULL
    assert(md != NULL);  // unclear if this is necessary
    // OpenSSL documentation allows s to be NULL

    ctx->is_initialized = nondet_bool();

    // Unclear if a failure when ctx is initialized will always leave it initialized

    return nondet_bool();  // OpenSSL documentation: 1 for success, 0 for failure
}

const EVP_MD *EVP_sha512() {
    EVP_MD *md;
    // OpenSSL implementation returns the address of a static struct, therefore can assume is not NULL
    __CPROVER_assume(md != NULL);
    return md;
}
