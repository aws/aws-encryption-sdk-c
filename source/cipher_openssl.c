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

#include <assert.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <aws/common/encoding.h>

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/cipher.h>

#include <ctype.h>
#include <stdio.h>

/* This is large enough to hold an encoded public key for all currently supported curves */
#define MAX_PUBKEY_SIZE 64
#define MAX_PUBKEY_SIZE_B64 (((MAX_PUBKEY_SIZE + 2) * 4) / 3)

/*
 * This is larger than the sizes defined in cipher.c to account for certain versions of the Encryption SDK
 * for other languages which generated signatures of nondeterministic size.
 */

#define MAX_SIGNATURE_SIZE 128
#define MAX_SIGNATURE_SIZE_B64 (((MAX_SIGNATURE_SIZE + 2) * 4) / 3)

// Compatibility hacks for openssl API changes between major versions
#if OPENSSL_VERSION_NUMBER < 0x10100000
#    define OSSL_100
#endif

#ifdef OSSL_100

#    define EVP_MD_CTX_new EVP_MD_CTX_create
#    define EVP_MD_CTX_free EVP_MD_CTX_destroy

static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **r, const BIGNUM **s) {
    *r = sig->r;
    *s = sig->s;
}

static void ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
    if (sig->r) BN_free(sig->r);
    if (sig->s) BN_free(sig->s);

    sig->r = r;
    sig->s = s;
}

#endif

struct aws_cryptosdk_sig_ctx {
    struct aws_allocator *alloc;
    const struct aws_cryptosdk_alg_properties *props;
    EC_KEY *keypair;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    bool is_sign;
};

bool aws_cryptosdk_sig_ctx_is_valid(const struct aws_cryptosdk_sig_ctx *sig_ctx) {
    return sig_ctx && AWS_OBJECT_PTR_IS_READABLE(sig_ctx->alloc) && AWS_OBJECT_PTR_IS_READABLE(sig_ctx->props) &&
           sig_ctx->keypair && sig_ctx->pkey && sig_ctx->ctx &&
#if OPENSSL_VERSION_NUMBER >= 0x10100000
           (EVP_PKEY_get0_EC_KEY(sig_ctx->pkey) == sig_ctx->keypair) &&
#endif
           (sig_ctx->is_sign == (EC_KEY_get0_private_key(sig_ctx->keypair) != NULL));
}

struct aws_cryptosdk_md_context {
    struct aws_allocator *alloc;
    EVP_MD_CTX *evp_md_ctx;
};

bool aws_cryptosdk_md_context_is_valid(const struct aws_cryptosdk_md_context *md_context) {
    return md_context && AWS_OBJECT_PTR_IS_READABLE(md_context->alloc) && md_context->evp_md_ctx;
}

int aws_cryptosdk_md_init(
    struct aws_allocator *alloc, struct aws_cryptosdk_md_context **md_context, enum aws_cryptosdk_md_alg md_alg) {
    const EVP_MD *evp_md_alg;
    *md_context = NULL;

    switch (md_alg) {
        case AWS_CRYPTOSDK_MD_SHA512: evp_md_alg = EVP_sha512(); break;
        default: return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_new();
    if (!evp_md_ctx) {
        aws_raise_error(AWS_ERROR_OOM);
        goto err;
    }

    if (1 != EVP_DigestInit_ex(evp_md_ctx, evp_md_alg, NULL)) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto err;
    }

    *md_context = aws_mem_acquire(alloc, sizeof(**md_context));
    if (!*md_context) {
        goto err;
    }

    (*md_context)->alloc      = alloc;
    (*md_context)->evp_md_ctx = evp_md_ctx;

    AWS_POSTCONDITION(aws_cryptosdk_md_context_is_valid(*md_context));
    return AWS_OP_SUCCESS;
err:
    EVP_MD_CTX_destroy(evp_md_ctx);
    return AWS_OP_ERR;
}

size_t aws_cryptosdk_md_size(enum aws_cryptosdk_md_alg md_alg) {
    switch (md_alg) {
        case AWS_CRYPTOSDK_MD_SHA512: return 512 / 8;
        default: return 0;
    }
}

int aws_cryptosdk_md_update(struct aws_cryptosdk_md_context *md_context, const void *buf, size_t length) {
    AWS_PRECONDITION(aws_cryptosdk_md_context_is_valid(md_context));
    AWS_PRECONDITION(AWS_MEM_IS_READABLE(buf, length));

    if (1 != EVP_DigestUpdate(md_context->evp_md_ctx, buf, length)) {
        AWS_POSTCONDITION(aws_cryptosdk_md_context_is_valid(md_context));
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    AWS_POSTCONDITION(aws_cryptosdk_md_context_is_valid(md_context));
    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_md_finish(struct aws_cryptosdk_md_context *md_context, void *output_buf, size_t *length) {
    AWS_PRECONDITION(aws_cryptosdk_md_context_is_valid(md_context));
    AWS_PRECONDITION(AWS_OBJECT_PTR_IS_READABLE(length));
    AWS_PRECONDITION(AWS_MEM_IS_WRITABLE(output_buf, *length));

    int rv            = AWS_OP_SUCCESS;
    unsigned int size = 0;

    // Replace with AWS_FATAL_PRECONDITION once that version is integrated
    if (!output_buf) {
        abort();
    }

    if (1 != EVP_DigestFinal_ex(md_context->evp_md_ctx, output_buf, &size)) {
        rv   = aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        size = 0;
    }

    *length = size;

    aws_cryptosdk_md_abort(md_context);

    return rv;
}

void aws_cryptosdk_md_abort(struct aws_cryptosdk_md_context *md_context) {
    AWS_PRECONDITION(!md_context || aws_cryptosdk_md_context_is_valid(md_context));
    if (!md_context) {
        return;
    }

    EVP_MD_CTX_destroy(md_context->evp_md_ctx);
    aws_mem_release(md_context->alloc, md_context);
}

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
 * Set up a signing context using a previously prepared EC_KEY. This will take a reference on keypair, so the caller
 * should dispose of its own reference on keypair.
 */
static struct aws_cryptosdk_sig_ctx *sign_start(
    struct aws_allocator *alloc, EC_KEY *keypair, const struct aws_cryptosdk_alg_properties *props) {
    struct aws_cryptosdk_sig_ctx *ctx = aws_mem_acquire(alloc, sizeof(*ctx));

    if (!ctx) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->alloc   = alloc;
    ctx->props   = props;
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

static int serialize_pubkey(struct aws_allocator *alloc, EC_KEY *keypair, struct aws_string **pub_key) {
    unsigned char *buf = NULL;
    int length;
    size_t b64_len;
    struct aws_byte_cursor binary;
    struct aws_byte_buf b64;
    uint8_t tmp[MAX_PUBKEY_SIZE_B64];

    // TODO: We currently _only_ accept compressed points. Should we accept uncompressed points as well?
    EC_KEY_set_conv_form(keypair, POINT_CONVERSION_COMPRESSED);

    length = i2o_ECPublicKey(keypair, &buf);
    if (length <= 0) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto err;
    }

    binary = aws_byte_cursor_from_array(buf, length);
    b64    = aws_byte_buf_from_empty_array(tmp, sizeof(tmp));

    if (aws_base64_compute_encoded_len(length, &b64_len)) {
        goto err;
    }

    /* This performs an implicit bounds check on MAX_PUBKEY_SIZE */
    if (aws_base64_encode(&binary, &b64)) {
        goto err;
    }

    // base64_encode adds a NUL terminator; strip it off
    // TODO: When aws-c-common removes the NUL terminator fix this
    if (b64.len && b64.buffer[b64.len - 1] == 0) {
        b64.len--;
    }

    *pub_key = aws_string_new_from_array(alloc, b64.buffer, b64.len);
    if (!*pub_key) {
        goto err;
    }

    free(buf);
    return AWS_OP_SUCCESS;

err:
    // buf (and tmp) hold a public key, so we don't need to zeroize them.
    free(buf);

    *pub_key = NULL;

    return AWS_OP_ERR;
}

int aws_cryptosdk_sig_get_pubkey(
    const struct aws_cryptosdk_sig_ctx *ctx, struct aws_allocator *alloc, struct aws_string **pub_key_buf) {
    return serialize_pubkey(alloc, ctx->keypair, pub_key_buf);
}

int aws_cryptosdk_sig_get_privkey(
    const struct aws_cryptosdk_sig_ctx *ctx, struct aws_allocator *alloc, struct aws_string **priv_key) {
    /*
     * When serializing private keys we use this ad-hoc format:
     *
     * 1. CryptoSDK algorithm ID (16-bit, big endian)
     * 2. Public key length (8-bit)
     * 3. Private key length (8-bit)
     * 4. Public key (DER, compressed point format)
     * 5. Private key (as an ASN.1 integer)
     *
     * We avoid the use of the d2i_ECPrivateKey format because it serializes the group,
     * and we have no reliable way of checking whether the deserialized group was correct.
     * In particular, EC_GROUP_cmp returns a non-equal result if the "method" of the group
     * differs (i.e. if one uses a generic EC backend, and the other uses an optimized backend
     * for the specific group). This can happen if i2d_ECPrivateKey chose an explicit curve
     * representation, which got loaded as a generic curve, while internally we choose a named
     * curve for the curve to compare against.
     */
    unsigned char *privkey_buf = NULL, *pubkey_buf = NULL;
    ASN1_INTEGER *privkey_int = NULL;
    /* Should be long enough to encode the private + compressed public key + alg id */
    unsigned char tmparr[MAX_PUBKEY_SIZE * 2 + 2];

    int privkey_len = 0, pubkey_len = 0;
    int rv                       = AWS_OP_ERR;
    struct aws_byte_buf tmpbuf   = aws_byte_buf_from_array(tmparr, sizeof(tmparr));
    struct aws_byte_cursor input = { 0 };

    const uint16_t alg_id = aws_hton16(ctx->props->alg_id);

    *priv_key = NULL;

    privkey_int = BN_to_ASN1_INTEGER(EC_KEY_get0_private_key(ctx->keypair), NULL);
    if (!privkey_int) {
        aws_raise_error(AWS_ERROR_OOM);
        goto err;
    }

    privkey_len = i2d_ASN1_INTEGER(privkey_int, &privkey_buf);

    /*
     * Clear and free the private key ASN1 string immediately, regardless of the success
     * or failure of serialization, to simplify error handling.
     */
    ASN1_STRING_clear_free(privkey_int);
    privkey_int = NULL;

    EC_KEY_set_conv_form(ctx->keypair, POINT_CONVERSION_COMPRESSED);
    pubkey_len = i2o_ECPublicKey(ctx->keypair, &pubkey_buf);

    if (!privkey_buf || !pubkey_buf) {
        aws_raise_error(AWS_ERROR_OOM);
        goto err;
    }

    if (privkey_len > 0xFF || pubkey_len > 0xFF) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto err;
    }

    tmpbuf.len = 0;
    /* TODO: Refactor once writing routines are moved to aws_byte_bufs */
    input = aws_byte_cursor_from_array((const uint8_t *)&alg_id, sizeof(alg_id));
    if (aws_byte_buf_append(&tmpbuf, &input)) {
        goto err;
    }
    tmpbuf.buffer[tmpbuf.len++] = pubkey_len;
    tmpbuf.buffer[tmpbuf.len++] = privkey_len;

    input = aws_byte_cursor_from_array(pubkey_buf, pubkey_len);
    if (aws_byte_buf_append(&tmpbuf, &input)) {
        goto err;
    }

    input = aws_byte_cursor_from_array(privkey_buf, privkey_len);
    if (aws_byte_buf_append(&tmpbuf, &input)) {
        goto err;
    }

    // Since this is an internal-only value, we don't bother with base64-encoding.
    *priv_key = aws_string_new_from_array(alloc, tmpbuf.buffer, tmpbuf.len);
    if (!*priv_key) {
        // OOM
        goto err;
    }

    rv = AWS_OP_SUCCESS;
err:
    aws_secure_zero(tmparr, sizeof(tmparr));
    if (privkey_buf) {
        aws_secure_zero(privkey_buf, privkey_len);
        free(privkey_buf);
    }
    if (pubkey_buf) {
        aws_secure_zero(pubkey_buf, pubkey_len);
        free(pubkey_buf);
    }

    // There is no error path that results in a non-NULL priv_key, so we don't need to
    // clean that up.

    return rv;
}

int aws_cryptosdk_sig_sign_start_keygen(
    struct aws_cryptosdk_sig_ctx **pctx,
    struct aws_allocator *alloc,
    struct aws_string **pub_key,
    const struct aws_cryptosdk_alg_properties *props) {
    EC_GROUP *group = NULL;
    EC_KEY *keypair = NULL;

    *pctx = NULL;
    if (pub_key) {
        *pub_key = NULL;
    }

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

    if (!EC_KEY_set_group(keypair, group)) {
        goto err;
    }

    if (!EC_KEY_generate_key(keypair)) {
        goto err;
    }

    if (pub_key && serialize_pubkey(alloc, keypair, pub_key)) {
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

    aws_string_destroy(*pub_key);
    *pub_key = NULL;

    EC_KEY_free(keypair);
    EC_GROUP_free(group);

    return AWS_OP_ERR;
}

void aws_cryptosdk_sig_abort(struct aws_cryptosdk_sig_ctx *ctx) {
    AWS_PRECONDITION(!ctx || (aws_cryptosdk_sig_ctx_is_valid(ctx) && AWS_OBJECT_PTR_IS_READABLE(ctx->alloc)));

    if (!ctx) {
        return;
    }

    EVP_MD_CTX_free(ctx->ctx);
    EVP_PKEY_free(ctx->pkey);
    EC_KEY_free(ctx->keypair);

    aws_mem_release(ctx->alloc, ctx);
}

int aws_cryptosdk_sig_sign_start(
    struct aws_cryptosdk_sig_ctx **ctx,
    struct aws_allocator *alloc,
    struct aws_string **pub_key_str,
    const struct aws_cryptosdk_alg_properties *props,
    const struct aws_string *priv_key) {
    /* See comments in aws_cryptosdk_sig_get_privkey re the serialized format */

    *ctx = NULL;
    if (pub_key_str) {
        *pub_key_str = NULL;
    }

    if (!props->impl->curve_name) {
        return AWS_OP_SUCCESS;
    }

    if (priv_key->len < 5) {
        // We don't have room for the algorithm ID plus the serialized private key.
        // Someone has apparently handed us a truncated private key?
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    EC_KEY *keypair             = NULL;
    EC_GROUP *group             = NULL;
    ASN1_INTEGER *priv_key_asn1 = NULL;
    BIGNUM *priv_key_bn         = NULL;

    struct aws_byte_cursor cursor = aws_byte_cursor_from_string(priv_key);
    struct aws_byte_cursor field;
    uint16_t serialized_alg_id;
    uint8_t privkey_len, pubkey_len;
    const uint8_t *bufp;
    int rv;

    if (!aws_byte_cursor_read_be16(&cursor, &serialized_alg_id) || !aws_byte_cursor_read_u8(&cursor, &pubkey_len) ||
        !aws_byte_cursor_read_u8(&cursor, &privkey_len)) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto out;
    }

    if (serialized_alg_id != props->alg_id) {
        // Algorithm mismatch
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (!(keypair = EC_KEY_new())) {
        aws_raise_error(AWS_ERROR_OOM);
        goto out;
    }

    if (!(group = group_for_props(props))) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto out;
    }

    if (!EC_KEY_set_group(keypair, group)) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        EC_GROUP_free(group);
        goto out;
    }
    EC_GROUP_free(group);
    EC_KEY_set_conv_form(keypair, POINT_CONVERSION_COMPRESSED);

    field = aws_byte_cursor_advance(&cursor, pubkey_len);
    bufp  = field.ptr;

    if (!field.ptr || !o2i_ECPublicKey(&keypair, &bufp, field.len) || bufp != field.ptr + field.len) {
        ERR_print_errors_fp(stderr);
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto out;
    }

    field = aws_byte_cursor_advance(&cursor, privkey_len);
    bufp  = field.ptr;

    if (!field.ptr || !d2i_ASN1_INTEGER(&priv_key_asn1, &bufp, field.len) || bufp != field.ptr + field.len) {
        ASN1_STRING_clear_free(priv_key_asn1);
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto out;
    }

    priv_key_bn = ASN1_INTEGER_to_BN(priv_key_asn1, NULL);
    // ASN1_INTEGERS are really ASN1_STRINGS; since there's no ASN1_INTEGER_clear_free, we'll use
    // ASN1_STRING_clear_free instead.
    ASN1_STRING_clear_free(priv_key_asn1);
    if (!priv_key_bn) {
        aws_raise_error(AWS_ERROR_OOM);
        goto out;
    }

    rv = EC_KEY_set_private_key(keypair, priv_key_bn);
    BN_clear_free(priv_key_bn);
    if (!rv) {
        aws_raise_error(AWS_ERROR_OOM);
        goto out;
    }

    if (cursor.len) {
        // Trailing garbage in the serialized private key
        // This should never happen, as this is an internal (trusted) datapath, but
        // check anyway
        aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        goto out;
    }

    if (pub_key_str && serialize_pubkey(alloc, keypair, pub_key_str)) {
        EC_KEY_free(keypair);
        return AWS_OP_ERR;
    }

    *ctx = sign_start(alloc, keypair, props);
    if (!*ctx && pub_key_str) {
        aws_string_destroy(*pub_key_str);
        *pub_key_str = NULL;
    }

out:
    // EC_KEYs are reference counted
    EC_KEY_free(keypair);
    return *ctx ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int load_pubkey(
    EC_KEY **key, const struct aws_cryptosdk_alg_properties *props, const struct aws_string *pub_key_s) {
    int result                              = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    EC_GROUP *group                         = NULL;
    uint8_t b64_decode_arr[MAX_PUBKEY_SIZE] = { 0 };
    struct aws_byte_buf b64_decode_buf      = aws_byte_buf_from_array(b64_decode_arr, sizeof(b64_decode_arr));
    struct aws_byte_cursor pub_key          = aws_byte_cursor_from_string(pub_key_s);

    *key = NULL;

    if (aws_base64_decode(&pub_key, &b64_decode_buf)) {
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
    if (*key == NULL) {
        result = AWS_ERROR_OOM;
        goto out;
    }
    // We must set the group before decoding, to allow openssl to decompress the point
    if (!EC_KEY_set_group(*key, group)) {
        result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
        goto out;
    }
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
    struct aws_cryptosdk_sig_ctx **pctx,
    struct aws_allocator *alloc,
    const struct aws_string *pub_key,
    const struct aws_cryptosdk_alg_properties *props) {
    AWS_PRECONDITION(pctx);
    AWS_PRECONDITION(alloc);
    AWS_PRECONDITION(aws_string_is_valid(pub_key));
    AWS_PRECONDITION(props);
    EC_KEY *key                       = NULL;
    struct aws_cryptosdk_sig_ctx *ctx = NULL;

    *pctx = NULL;

    if (!props->impl->curve_name) {
        AWS_POSTCONDITION(!*pctx);
        AWS_POSTCONDITION(aws_string_is_valid(pub_key));
        return AWS_OP_SUCCESS;
    }

    if (load_pubkey(&key, props, pub_key)) {
        AWS_POSTCONDITION(!*pctx);
        AWS_POSTCONDITION(aws_string_is_valid(pub_key));
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
    key          = NULL;

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
    *pctx        = ctx;

    AWS_POSTCONDITION(aws_cryptosdk_sig_ctx_is_valid(*pctx));
    AWS_POSTCONDITION(!(*pctx)->is_sign);
    AWS_POSTCONDITION(aws_string_is_valid(pub_key));
    return AWS_OP_SUCCESS;

oom:
    aws_raise_error(AWS_ERROR_OOM);
rethrow:
    EC_KEY_free(key);
    if (ctx) {
        aws_cryptosdk_sig_abort(ctx);
    }

    AWS_POSTCONDITION(!*pctx);
    AWS_POSTCONDITION(aws_string_is_valid(pub_key));
    return AWS_OP_ERR;
}

int aws_cryptosdk_sig_update(struct aws_cryptosdk_sig_ctx *ctx, const struct aws_byte_cursor cursor) {
    AWS_PRECONDITION(aws_cryptosdk_sig_ctx_is_valid(ctx));
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&cursor));

    if (cursor.len == 0) {
        /* Nothing to do */
        AWS_POSTCONDITION(aws_cryptosdk_sig_ctx_is_valid(ctx));
        AWS_POSTCONDITION(aws_byte_cursor_is_valid(&cursor));
        return AWS_OP_SUCCESS;
    }

    if (EVP_DigestUpdate(ctx->ctx, cursor.ptr, cursor.len) != 1) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    AWS_POSTCONDITION(aws_cryptosdk_sig_ctx_is_valid(ctx));
    AWS_POSTCONDITION(aws_byte_cursor_is_valid(&cursor));
    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_sig_verify_finish(struct aws_cryptosdk_sig_ctx *ctx, const struct aws_string *signature) {
    AWS_PRECONDITION(aws_cryptosdk_sig_ctx_is_valid(ctx));
    AWS_PRECONDITION(ctx->alloc);
    AWS_PRECONDITION(!ctx->is_sign);
    AWS_PRECONDITION(aws_string_is_valid(signature));
    bool ok = EVP_DigestVerifyFinal(ctx->ctx, aws_string_bytes(signature), signature->len) == 1;

    aws_cryptosdk_sig_abort(ctx);

    return ok ? AWS_OP_SUCCESS : aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
}

int aws_cryptosdk_sig_sign_finish(
    struct aws_cryptosdk_sig_ctx *ctx, struct aws_allocator *alloc, struct aws_string **signature) {
    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    /* This needs to be big enough for all digest algorithms in use */
    uint8_t digestbuf[64];

    EVP_PKEY_CTX *sign_ctx     = NULL;
    ECDSA_SIG *sig             = NULL;
    struct aws_byte_buf sigtmp = { 0 };

    size_t digestlen, siglen;
    assert(ctx->is_sign);

    digestlen = EVP_MD_CTX_size(ctx->ctx);

    const EC_GROUP *group = EC_KEY_get0_group(ctx->keypair);
#ifndef OSSL_100
    const BIGNUM *order = EC_GROUP_get0_order(group);
#else
    BIGNUM *order = BN_new();

    if (!order || !EC_GROUP_get_order(group, order, NULL)) {
        result = AWS_ERROR_OOM;
        goto out;
    }
#endif

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
    if (aws_byte_buf_init(&sigtmp, alloc, siglen)) {
        goto rethrow;
    }

    sigtmp.len = 0;

    while (sigtmp.len != ctx->props->signature_len) {
        sigtmp.len = sigtmp.capacity;
        if (1 != EVP_PKEY_sign(sign_ctx, sigtmp.buffer, &sigtmp.len, digestbuf, digestlen)) {
            goto out;
        }

        if (sigtmp.len == ctx->props->signature_len) {
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
         * signature). If this fails, we'll just generate a brand new signature;
         * since ECDSA signatures contain a random component, this will usually either
         * get us to the desired size directly, or at least make it so the negation
         * trick works.
         */
        const unsigned char *psig = sigtmp.buffer;
        if (d2i_ECDSA_SIG(&sig, &psig, sigtmp.len)) {
            const BIGNUM *orig_r, *orig_s;
            ECDSA_SIG_get0(sig, (const BIGNUM **)&orig_r, (const BIGNUM **)&orig_s);

            BIGNUM *r = BN_dup(orig_r);
            BIGNUM *s = BN_dup(orig_s);

            if (!r || !s) {
                result = AWS_ERROR_OOM;
                goto out;
            }

            if (!BN_sub(s, order, s)) {
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

            unsigned char *poutsig = sigtmp.buffer;
            if (!i2d_ECDSA_SIG(sig, &poutsig)) {
                goto out;
            }

            sigtmp.len = poutsig - sigtmp.buffer;
        }

        ECDSA_SIG_free(sig);
        sig = NULL;
    }

    *signature = aws_string_new_from_array(alloc, sigtmp.buffer, sigtmp.len);
    if (!*signature) {
        goto rethrow;
    }

    result = AWS_OP_SUCCESS;
out:
    if (result != AWS_OP_SUCCESS) aws_raise_error(result);
rethrow:
#ifdef OSSL_100
    BN_free(order);
#endif
    EVP_PKEY_CTX_free(sign_ctx);
    aws_cryptosdk_sig_abort(ctx);
    aws_secure_zero(digestbuf, sizeof(digestbuf));
    aws_byte_buf_clean_up(&sigtmp);
    ECDSA_SIG_free(sig);

    if (result) {
        // We shouldn't have actually allocated signature, so just make sure it's NULL on an error path
        *signature = NULL;
    }

    return result ? AWS_OP_ERR : AWS_OP_SUCCESS;
}
