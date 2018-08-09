/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include <assert.h>
#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/hkdf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static int aws_cryptosdk_hkdf_extract(
    uint8_t *prk,
    unsigned int *prk_len,
    enum aws_cryptosdk_sha_version which_sha,
    const struct aws_byte_buf *salt,
    const struct aws_byte_buf *ikm) {
    uint8_t zeroes[EVP_MAX_MD_SIZE] = { 0 };
    uint8_t *mysalt = NULL;
    size_t mysalt_len = 0;
    const EVP_MD *evp_md = (which_sha == SHA256) ? EVP_sha256() : EVP_sha384();
    assert(evp_md != NULL);

    if (salt->len) {
        mysalt = (uint8_t *)salt->buffer;
        mysalt_len = salt->len;
    } else {
        mysalt = zeroes;
        mysalt_len = EVP_MAX_MD_SIZE;
    }

    if (!HMAC(evp_md, mysalt, mysalt_len, ikm->buffer, ikm->len, prk, prk_len)) {
        aws_secure_zero(prk, sizeof(prk));
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }
    return AWS_OP_SUCCESS;
}

static int aws_cryptosdk_hkdf_expand(
    struct aws_byte_buf *okm,
    enum aws_cryptosdk_sha_version which_sha,
    const uint8_t *prk,
    size_t prk_len,
    const struct aws_byte_buf *info) {
    HMAC_CTX ctx;
    uint8_t t[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    unsigned int t_len = 0;
    unsigned int bytes_to_write;
    unsigned int bytes_remaining = okm->len;
    const EVP_MD *evp_md = (which_sha == SHA256) ? EVP_sha256() : EVP_sha384();
    const size_t hash_len = EVP_MD_size(evp_md);

    HMAC_CTX_init(&ctx);

    if (!prk || !okm->len || !prk_len) goto err;
    n = (okm->len + hash_len - 1) / hash_len;
    if (n > 255) goto err;

    for (uint8_t idx = 1; idx <= n; idx++) {
        if (!HMAC_Init_ex(&ctx, prk, prk_len, evp_md, NULL)) goto err;
        if (idx != 1) {
            if (!HMAC_Update(&ctx, t, hash_len)) goto err;
        }
        if (!HMAC_Update(&ctx, info->buffer, info->len)) goto err;
        if (!HMAC_Update(&ctx, &idx, 1)) goto err;
        if (!HMAC_Final(&ctx, t, &t_len)) goto err;

        assert(t_len == hash_len);
        bytes_to_write = bytes_remaining < hash_len ? bytes_remaining : hash_len;
        memcpy(okm->buffer + (idx - 1) * hash_len, t, bytes_to_write);
        bytes_remaining -= bytes_to_write;
    }
    assert(bytes_remaining == 0);
    aws_secure_zero(t, sizeof(t));
    HMAC_CTX_cleanup(&ctx);
    return AWS_OP_SUCCESS;

err:
    HMAC_CTX_cleanup(&ctx);
    aws_byte_buf_secure_zero(okm);
    aws_secure_zero(t, sizeof(t));
    return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
}
#else
#    include <openssl/kdf.h>

static int aws_cryptosdk_openssl_hkdf_version(
    struct aws_byte_buf *okm,
    enum aws_cryptosdk_sha_version which_sha,
    const struct aws_byte_buf *salt,
    const struct aws_byte_buf *ikm,
    const struct aws_byte_buf *info) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    const EVP_MD *evp_md = (which_sha == SHA256) ? EVP_sha256() : EVP_sha384();

    if (!pctx) return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    if (EVP_PKEY_derive_init(pctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, evp_md) <= 0) goto err;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt->buffer, salt->len) <= 0) goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm->buffer, ikm->len) <= 0) goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info->buffer, info->len) <= 0) goto err;
    if (EVP_PKEY_derive(pctx, okm->buffer, &okm->len) <= 0) goto err;

    EVP_PKEY_CTX_free(pctx);
    return AWS_OP_SUCCESS;

err:
    EVP_PKEY_CTX_free(pctx);
    aws_byte_buf_secure_zero(okm);
    return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
}
#endif  // OPENSSL_VERSION_NUMBER

int aws_cryptosdk_hkdf(
    struct aws_byte_buf *okm,
    enum aws_cryptosdk_sha_version which_sha,
    const struct aws_byte_buf *salt,
    const struct aws_byte_buf *ikm,
    const struct aws_byte_buf *info) {
    assert ( SHA256 <= which_sha >= SHA384 );
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    uint8_t prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len;
    if (aws_cryptosdk_hkdf_extract(prk, &prk_len, which_sha, salt, ikm)) goto err;
    if (aws_cryptosdk_hkdf_expand(okm, which_sha, prk, prk_len, info)) goto err;
    aws_secure_zero(prk, sizeof(prk));
    return AWS_OP_SUCCESS;
err:
    aws_secure_zero(prk, sizeof(prk));
    return AWS_OP_ERR;
#else
    return aws_cryptosdk_openssl_hkdf_version(okm, which_sha, salt, ikm, info);
#endif  // OPENSSL_VERSION_NUMBER
}
