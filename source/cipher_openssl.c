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

#include <stdlib.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include <aws/common/encoding.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/cipher.h>

struct aws_cryptosdk_signctx {
    struct aws_allocator *alloc;
    const struct aws_cryptosdk_alg_properties *props;
    EC_KEY *keypair;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    bool is_sign;
};


static EC_GROUP *group_for_props(const struct aws_cryptosdk_alg_properties *props) {
    // TODO: Cache? Are EC_GROUPs threadsafe?

    int nid = OBJ_txt2nid(props->impl->curve_name);
    if (nid == NID_undef) {
        fprintf(stderr, "Unknown curve %s\n", props->impl->curve_name);
        // unknown curve
        return NULL;
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (group) {
        EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);
    }

    return group;
}

/**
 * Verify that 'group' is the correct ECDSA group to use for the algorithm suite in props.
 * This is used when deserializing a private key; public keys don't carry group info, so
 * in that case we can just decompress the point using the correct group.
 */
static bool is_group_correct(const EC_GROUP *group, const struct aws_cryptosdk_alg_properties *props) {
    EC_GROUP *check_group = group_for_props(props);

    bool ok = (check_group == group || !EC_GROUP_cmp(group, check_group, NULL));

    EC_GROUP_free(check_group);

    return ok;
}

/**
 * Set up a signing context using a previously prepared EC_KEY. This will take a reference on keypair, so the caller
 * should dispose of its own reference on keypair.
 */
static struct aws_cryptosdk_signctx *sign_start(struct aws_allocator *alloc, EC_KEY *keypair, const struct aws_cryptosdk_alg_properties *props) {
    struct aws_cryptosdk_signctx *ctx = aws_mem_acquire(alloc, sizeof(*ctx));

    if (!ctx) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->alloc = alloc;
    ctx->props = props;
    ctx->keypair = keypair;
    // The caller will unconditionally clean up the EC_KEY, so up the refcount first
    EC_KEY_up_ref(ctx->keypair);

    if (!(ctx->pkey = EVP_PKEY_new())) {
        goto oom;
    }

    if (!EVP_PKEY_set1_EC_KEY(ctx->pkey, ctx->keypair)) {
        goto oom;
    }

    if (!(ctx->ctx = EVP_MD_CTX_new())) {
        goto oom;
    }

    /*
     * We perform the digest and signature separately, as we might need to re-sign to get the right
     * signature size.
     */
    if (!(EVP_DigestInit(ctx->ctx, props->impl->md_ctor()))) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto rethrow;
    }

    ctx->is_sign = true;

    return ctx;

oom:
    aws_raise_error(AWS_ERROR_OOM);
rethrow:
    aws_cryptosdk_sig_abort(ctx);

    return NULL;
}

static int serialize_pubkey(struct aws_allocator *alloc, EC_KEY *keypair, struct aws_byte_buf *pub_key) {
    unsigned char *buf = NULL;
    int length;
    size_t b64_len;
    struct aws_byte_buf binary;

    // TODO: We currently _only_ accept compressed points. Should we accept uncompressed points as well?
    EC_KEY_set_conv_form(keypair, POINT_CONVERSION_COMPRESSED);

    length = i2o_ECPublicKey(keypair, &buf);
    if (length < 0) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto err;
    }

    binary = aws_byte_buf_from_array(buf, length);

    if (aws_base64_compute_encoded_len(length, &b64_len)) {
        goto err;
    }

    if (aws_byte_buf_init(alloc, pub_key, b64_len)) {
        goto err;
    }

    if (aws_base64_encode(&binary, pub_key)) {
        goto err;
    }

    // base64_encode adds a NUL terminator; strip it off
    // TODO: When aws-c-common removes the NUL terminator fix this
    if (pub_key->len && pub_key->buffer[pub_key->len - 1] == 0) {
        pub_key->len--;
    }

    free(buf);
    return AWS_OP_SUCCESS;

err:
    aws_secure_zero(buf, length);
    free(buf);
    aws_byte_buf_secure_zero(pub_key);

    return AWS_OP_ERR;
}

int aws_cryptosdk_sig_get_privkey(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx *ctx,
    struct aws_byte_buf *priv_key_buf
) {
    unsigned char *buf = NULL;
    int length;
    struct aws_byte_buf binary;

    memset(priv_key_buf, 0, sizeof(*priv_key_buf));

    /* buf is allocated on the C heap */
    length = i2d_ECPrivateKey(ctx->keypair, &buf);
    if (length < 0) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto err;
    }

    // Since this is an internal-only value, we don't bother with base64-encoding.
    // However, we do want to move it from the C allocator to the provided allocator

    binary = aws_byte_buf_from_array(buf, length);
    if (aws_byte_buf_init_copy(alloc, priv_key_buf, &binary)) {
        goto err;
    }

    free(buf);

    return AWS_OP_SUCCESS;
err:
    aws_secure_zero(buf, length);
    free(buf);
    aws_byte_buf_clean_up_secure(priv_key_buf);

    return AWS_OP_ERR;
}

int aws_cryptosdk_sig_keygen(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx **pctx,
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_buf *pub_key_buf
) {
    EC_GROUP *group = NULL;
    EC_KEY *keypair = NULL;

    *pctx = NULL;
    memset(pub_key_buf, 0, sizeof(*pub_key_buf));

    if (!props->impl->curve_name) {
        return AWS_OP_SUCCESS;
    }

    group = group_for_props(props);
    if (!group) {
        goto err;
    }

    if (!(keypair = EC_KEY_new())) {
        goto err;
    }

    EC_KEY_set_group(keypair, group);
    if (!EC_KEY_generate_key(keypair)) {
        goto err;
    }

    if (serialize_pubkey(alloc, keypair, pub_key_buf)) {
        goto rethrow;
    }

    *pctx = sign_start(alloc, keypair, props);
    if (!*pctx) {
        goto rethrow;
    }

    EC_KEY_free(keypair);
    EC_GROUP_free(group);

    return AWS_OP_SUCCESS;

err:
    aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
rethrow:
    aws_cryptosdk_sig_abort(*pctx);
    *pctx = NULL;

    aws_byte_buf_secure_zero(pub_key_buf);
    EC_KEY_free(keypair);
    EC_GROUP_free(group);

    return AWS_OP_ERR;
}

void aws_cryptosdk_sig_abort(
    struct aws_cryptosdk_signctx *ctx
) {
    if (!ctx) {
        return;
    }

    EVP_MD_CTX_free(ctx->ctx);
    EVP_PKEY_free(ctx->pkey);
    EC_KEY_free(ctx->keypair);

    aws_mem_release(ctx->alloc, ctx);
}

int aws_cryptosdk_sig_sign_start(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx **ctx,
    struct aws_byte_buf *pub_key_buf,
    const struct aws_cryptosdk_alg_properties *props,
    const struct aws_byte_buf *priv_key
) {
    *ctx = NULL;
    memset(pub_key_buf, 0, sizeof(*pub_key_buf));

    if (!props->impl->curve_name) {
        return AWS_OP_SUCCESS;
    }

    EC_KEY *keypair = NULL;
    const unsigned char *bufp = priv_key->buffer;
    if (!(keypair = d2i_ECPrivateKey(NULL, &bufp, priv_key->len))) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (!is_group_correct(EC_KEY_get0_group(keypair), props)) {
        EC_KEY_free(keypair);

        // This key didn't come from ciphertext, so don't report bad ciphertext
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (pub_key_buf && serialize_pubkey(alloc, keypair, pub_key_buf)) {
        EC_KEY_free(keypair);
        return AWS_OP_ERR;
    }

    *ctx = sign_start(alloc, keypair, props);
    if (!*ctx) {
        aws_byte_buf_secure_zero(pub_key_buf);
    }

    // EC_KEYs are reference counted
    EC_KEY_free(keypair);
    return *ctx ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int load_pubkey(EC_KEY **key, const struct aws_cryptosdk_alg_properties *props, struct aws_byte_buf *pub_key) {
    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    EC_GROUP *group = NULL;
    /* This buffer is large enough to hold compressed points for all currently supported curves */
    uint8_t b64_decode_arr[64];
    struct aws_byte_buf b64_decode_buf = aws_byte_buf_from_array(b64_decode_arr, sizeof(b64_decode_arr));

    *key = NULL;

    if (aws_base64_decode(pub_key, &b64_decode_buf)) {
        /*
         * This'll happen if e.g. the public key is too large (aws_base64_decode checks the output buffer capacity),
         * or if it's just bad base64.
         */
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    group = group_for_props(props);
    if (!group) {
        goto out;
    }

    *key = EC_KEY_new();
    // We must set the group before decoding, to allow openssl to decompress the point
    EC_KEY_set_group(*key, group);
    EC_KEY_set_conv_form(*key, POINT_CONVERSION_COMPRESSED);

    const unsigned char *pBuf = b64_decode_buf.buffer;

    if (!o2i_ECPublicKey(key, &pBuf, b64_decode_buf.len)) {
        result = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT;
        goto out;
    }

    result = AWS_OP_SUCCESS;
out:
    // The EC_KEY_set_group method copies the provided group.

    EC_GROUP_free(group);
    if (result) {
        EC_KEY_free(*key);
        *key = NULL;
    }
    aws_secure_zero(b64_decode_arr, sizeof(b64_decode_arr));

    return result ? aws_raise_error(result) : AWS_OP_SUCCESS;
}

int aws_cryptosdk_sig_verify_start(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx **pctx,
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_buf *pub_key
) {
    EC_KEY *key = NULL;
    struct aws_cryptosdk_signctx *ctx = NULL;

    *pctx = NULL;

    if (!props->impl->curve_name) {
        return AWS_OP_SUCCESS;
    }

    if (load_pubkey(&key, props, pub_key)) {
        return AWS_OP_ERR;
    }

    ctx = aws_mem_acquire(alloc, sizeof(*ctx));
    if (!ctx) {
        goto oom;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->alloc = alloc;
    ctx->props = props;

    if (!(ctx->pkey = EVP_PKEY_new())) {
        goto oom;
    }

    ctx->keypair = key;
    key = NULL;

    if (!EVP_PKEY_set1_EC_KEY(ctx->pkey, ctx->keypair)) {
        goto oom;
    }

    if (!(ctx->ctx = EVP_MD_CTX_new())) {
        goto oom;
    }

    if (!(EVP_DigestVerifyInit(ctx->ctx, NULL, props->impl->md_ctor(), NULL, ctx->pkey))) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto rethrow;
    }

    ctx->is_sign = false;
    *pctx = ctx;

    return AWS_OP_SUCCESS;

oom:
    aws_raise_error(AWS_ERROR_OOM);
rethrow:
    EC_KEY_free(key);
    if (ctx) {
        aws_cryptosdk_sig_abort(ctx);
    }

    return AWS_OP_ERR;
}

int aws_cryptosdk_sig_update(
    struct aws_cryptosdk_signctx *ctx,
    const struct aws_byte_buf *buf
) {
    if (EVP_DigestUpdate(ctx->ctx, buf->buffer, buf->len) != 1) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_sig_verify_finish(
    struct aws_cryptosdk_signctx *ctx,
    const struct aws_byte_buf *signature
) {
    assert(!ctx->is_sign);
    bool ok = EVP_DigestVerifyFinal(ctx->ctx, signature->buffer, signature->len) == 1;

    aws_cryptosdk_sig_abort(ctx);

    return ok ? AWS_OP_SUCCESS : aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
}

int aws_cryptosdk_sig_sign_finish(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx *ctx,
    struct aws_byte_buf *signature
) {
    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    /* This needs to be big enough for all digest algorithms in use */
    uint8_t digestbuf[64];
    EVP_PKEY_CTX *sign_ctx = NULL;
    ECDSA_SIG *sig = NULL;

    size_t digestlen, siglen;
    assert(ctx->is_sign);

    digestlen = EVP_MD_CTX_size(ctx->ctx);

    if (digestlen > sizeof(digestbuf)) {
        /* Should never happen */
        goto out;
    }

    if (1 != EVP_DigestFinal(ctx->ctx, digestbuf, NULL)) {
        goto out;
    }

    sign_ctx = EVP_PKEY_CTX_new(ctx->pkey, NULL);
    if (!sign_ctx) {
        result = AWS_ERROR_OOM;
        goto out;
    }

    if (1 != EVP_PKEY_sign_init(sign_ctx)) {
        goto out;
    }

    if (1 != EVP_PKEY_sign(sign_ctx, NULL, &siglen, digestbuf, digestlen)) {
        goto out;
    }

    /*
     * Note that siglen is the maximum possible size of a EC signature,
     * which may differ from the size we have set for AWSES signatures.
     * We'll allocate that much for the buffer capacity, and use a combination
     * of EC math and re-signing to hit the target size.
     *
     * It's important to hit the target precisely, as the caller might have
     * relied on a precise calculation of the ciphertext size in order to
     * e.g. set the S3 content-length on a PutObject, or otherwise preallocate
     * the destination space.
     */
    if (aws_byte_buf_init(alloc, signature, siglen)) {
        goto rethrow;
    }

    while (signature->len != ctx->props->signature_len) {
        signature->len = signature->capacity;
        if (1 != EVP_PKEY_sign(sign_ctx, signature->buffer, &signature->len, digestbuf, digestlen)) {
            goto out;
        }

        if (signature->len == ctx->props->signature_len) {
            break;
        }

        /*
         * The unpredictability of the signature length arises from DER encoding
         * requiring an extra byte to represent integers where the high bit is
         * aligned with the high bit of a byte, and is set - this would result
         * in an encoding which appears to be negative.
         *
         * In the vast majority of cases, we can resolve this by negating s in the
         * signature relative to the group order (which does not invalidate the
         * signature); if this fails, we'll pick a new nonce by redoing the signature.
         */
        const unsigned char *psig = signature->buffer;
        if (d2i_ECDSA_SIG(&sig, &psig, signature->len)) {
            const EC_GROUP *group = EC_KEY_get0_group(ctx->keypair);
            const BIGNUM *order = EC_GROUP_get0_order(group);

            BIGNUM *r, *s;
            ECDSA_SIG_get0(sig, (const BIGNUM **)&r, (const BIGNUM **)&s);
            r = BN_dup(r);
            s = BN_dup(s);

            if (!r || !s) {
                result = AWS_ERROR_OOM;
                goto out;
            }

            if (!BN_sub(s,order,s)) {
                /* Signature values are not secret, so we just use BN_free here */
                BN_free(r);
                BN_free(s);
                goto out;
            }

            /*
             * This unconditionally frees the old r/s values, so it's important that
             * we BN_dup them above.
             */
            ECDSA_SIG_set0(sig, r, s);

            unsigned char *poutsig = signature->buffer;
            if (!i2d_ECDSA_SIG(sig, &poutsig)) {
                goto out;
            }

            signature->len = poutsig - signature->buffer;
        }

        ECDSA_SIG_free(sig);
        sig = NULL;
    }

    result = AWS_OP_SUCCESS;
out:
    if (result != AWS_OP_SUCCESS) aws_raise_error(result);
rethrow:
    EVP_PKEY_CTX_free(sign_ctx);
    aws_cryptosdk_sig_abort(ctx);
    aws_secure_zero(digestbuf, sizeof(digestbuf));
    ECDSA_SIG_free(sig);

    return result ? AWS_OP_ERR : AWS_OP_SUCCESS;
}
