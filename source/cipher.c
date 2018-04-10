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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <assert.h>
#include <arpa/inet.h>

#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/error.h>

#define MSG_ID_LEN 16

struct aws_cryptosdk_alg_impl {
    const EVP_MD *(*md_ctor)(void);
    const EVP_CIPHER *(*cipher_ctor)(void);
};

const struct aws_cryptosdk_alg_properties *aws_cryptosdk_alg_props(enum aws_cryptosdk_alg_id alg_id) {
#define EVP_NULL NULL
#define STATIC_ALG_PROPS(alg_id_v, md, cipher, dk_len_v, iv_len_v, tag_len_v) \
    case alg_id_v: { \
        static const struct aws_cryptosdk_alg_impl impl = { \
            .md_ctor = (EVP_##md), \
            .cipher_ctor = (EVP_##cipher), \
        }; \
        static const struct aws_cryptosdk_alg_properties props = { \
            .md_name = #md, \
            .cipher_name = #cipher, \
            .impl = &impl, \
            .data_key_len = (dk_len_v)/8, \
    /* Currently we don't support any algorithms where DK and CK lengths differ */ \
            .content_key_len = (dk_len_v)/8, \
            .iv_len = (iv_len_v), \
            .tag_len = (tag_len_v), \
            .alg_id = (alg_id_v) \
        }; \
        return &props; \
    }
    switch (alg_id) {
        STATIC_ALG_PROPS(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE,
            NULL, aes_128_gcm, 128, 12, 16);
        STATIC_ALG_PROPS(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
            sha256, aes_128_gcm, 128, 12, 16);
        STATIC_ALG_PROPS(AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE,
            NULL, aes_192_gcm, 192, 12, 16);
        STATIC_ALG_PROPS(AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
            sha256, aes_192_gcm, 192, 12, 16);
        STATIC_ALG_PROPS(AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE,
            NULL, aes_256_gcm, 256, 12, 16);
        STATIC_ALG_PROPS(AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
            sha256, aes_256_gcm, 256, 12, 16);
#if 0
        // Not yet supported
        STATIC_ALG_PROPS(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256,
            sha256, aes_128_gcm, 128, 12, 16);
        STATIC_ALG_PROPS(AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
            sha384, aes_192_gcm, 192, 12, 16);
        STATIC_ALG_PROPS(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
            sha384, aes_256_gcm, 256, 12, 16);
#endif
        default:
            return NULL;
    }
#undef STATIC_ALG_PROPS
#undef EVP_NULL
}

int aws_cryptosdk_derive_key(
    struct content_key *content_key,
    const struct data_key *data_key,
    enum aws_cryptosdk_alg_id alg_id,
    const uint8_t *message_id
) {
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    if (!props) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
    }

    aws_cryptosdk_secure_zero(content_key->keybuf, sizeof(content_key->keybuf));

    if (props->impl->md_ctor == NULL) {
        memcpy(content_key->keybuf, data_key->keybuf, props->data_key_len);
        return AWS_OP_SUCCESS;
    }

    EVP_PKEY_CTX *pctx;
    size_t outlen = props->content_key_len;

    uint8_t info[MSG_ID_LEN + 2];
    info[0] = alg_id >> 8;
    info[1] = alg_id & 0xFF;
    memcpy(&info[2], message_id, sizeof(info) - 2);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);

    if (EVP_PKEY_derive_init(pctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, props->impl->md_ctor()) <= 0) goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, data_key->keybuf, props->data_key_len) <= 0) goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info)) <= 0) goto err;
    if (EVP_PKEY_derive(pctx, content_key->keybuf, &outlen) <= 0) goto err;

    EVP_PKEY_CTX_free(pctx);

    return AWS_OP_SUCCESS;
err:
    EVP_PKEY_CTX_free(pctx);

    aws_cryptosdk_secure_zero(content_key->keybuf, sizeof(content_key->keybuf));
    return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
}

static EVP_CIPHER_CTX *evp_gcm_decrypt_init(
    const struct aws_cryptosdk_alg_properties *props,
    const struct content_key *content_key,
    const uint8_t *iv
) {
    EVP_CIPHER_CTX *ctx = NULL;

    if (!(ctx = EVP_CIPHER_CTX_new())) goto err;
    if (!EVP_DecryptInit_ex(ctx, props->impl->cipher_ctor(), NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, props->iv_len, NULL)) goto err;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, content_key->keybuf, iv)) goto err;

    return ctx;

err:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return NULL;
}

static int evp_gcm_decrypt_final(const struct aws_cryptosdk_alg_properties *props, EVP_CIPHER_CTX *ctx, const uint8_t *tag) {
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, props->tag_len, (void *)tag)) {
        return AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    }

    /*
     * Flush all error codes; if the GCM tag is invalid, openssl will fail without generating
     * an error code, so any leftover error codes will get in the way of detection.
     */
    while (ERR_get_error() != 0) {}

    int outlen;
    uint8_t finalbuf;

    if (!EVP_DecryptFinal_ex(ctx, &finalbuf, &outlen)) {
        if (ERR_peek_last_error() == 0) {
            return AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT;
        }
        return AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    }

    if (outlen != 0) {
        abort(); // wrong output size - potentially smashed stack
    }

    return AWS_ERROR_SUCCESS;
}

int aws_cryptosdk_verify_header(
    enum aws_cryptosdk_alg_id alg_id,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header
) {
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    if (!props) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
    }

    if (authtag->len != props->iv_len + props->tag_len) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    const uint8_t *iv = authtag->buffer;
    const uint8_t *tag = authtag->buffer + props->iv_len;
    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    EVP_CIPHER_CTX *ctx = evp_gcm_decrypt_init(props, content_key, iv);
    if (!ctx) goto out;

    int outlen;
    if (!EVP_DecryptUpdate(ctx, NULL, &outlen, header->buffer, header->len)) goto out;

    result = evp_gcm_decrypt_final(props, ctx, tag);
out:
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    if (result == AWS_ERROR_SUCCESS) {
        return AWS_OP_SUCCESS;
    } else {
        return aws_raise_error(result);
    }
}

static int update_frame_aad(
    EVP_CIPHER_CTX *ctx,
    const uint8_t *message_id,
    int body_frame_type,
    uint32_t seqno,
    uint64_t data_size
) {
    const char *aad_string;

    switch (body_frame_type) {
        case FRAME_TYPE_SINGLE: aad_string = "AWSKMSEncryptionClient Single Block"; break;
        case FRAME_TYPE_FRAME: aad_string = "AWSKMSEncryptionClient Frame"; break;
        case FRAME_TYPE_FINAL: aad_string = "AWSKMSEncryptionClient Final Frame"; break;
        default:
            return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    int ignored;

    if (!EVP_CipherUpdate(ctx, NULL, &ignored, message_id, MSG_ID_LEN)) return 0;
    if (!EVP_CipherUpdate(ctx, NULL, &ignored, (const uint8_t *)aad_string, strlen(aad_string))) return 0;

    seqno = htonl(seqno);
    if (!EVP_CipherUpdate(ctx, NULL, &ignored, (const uint8_t *)&seqno, sizeof(seqno))) return 0;

    uint32_t size[2];

    size[0] = htonl(data_size >> 32);
    size[1] = htonl(data_size & 0xFFFFFFFFUL);

    return EVP_CipherUpdate(ctx, NULL, &ignored, (const uint8_t *)size, sizeof(size));
}


int aws_cryptosdk_decrypt_body(
    struct aws_byte_cursor *out,
    const struct aws_byte_cursor *in,
    enum aws_cryptosdk_alg_id alg_id,
    const uint8_t *message_id,
    uint32_t seqno,
    const uint8_t *iv,
    const struct content_key *key,
    const uint8_t *tag,
    int body_frame_type
) {
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    if (!props) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
    }

    if (in->len != out->len) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    EVP_CIPHER_CTX *ctx = NULL;
    struct aws_byte_cursor outp = *out;
    struct aws_byte_cursor inp = *in;
    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    if (!(ctx = evp_gcm_decrypt_init(props, key, iv))) goto out;

    if (!update_frame_aad(ctx, message_id, body_frame_type, seqno, in->len)) goto out;

    while (inp.len) {
        int in_len = inp.len > INT_MAX ? INT_MAX : inp.len;
        int pt_len;

        if (!EVP_DecryptUpdate(ctx, outp.ptr, &pt_len, inp.ptr, in_len)) goto out;
        /*
         * The next two advances should never fail ... but check the return values
         * just in case.
         */
        if (!aws_byte_cursor_advance_nospec(&inp, in_len).ptr) goto out;
        if (!aws_byte_cursor_advance(&outp, pt_len).ptr) {
            /* Somehow we ran over the output buffer. abort() to limit the damage. */
            abort();
        }
    }

    result = evp_gcm_decrypt_final(props, ctx, tag);
out:
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    if (result == AWS_ERROR_SUCCESS) {
        return AWS_OP_SUCCESS;
    } else {
        memset(out->ptr, 0, out->len);
        return aws_raise_error(result);
    }
}

int aws_cryptosdk_genrandom(uint8_t *buf, size_t len) {
    int rc = RAND_bytes(buf, len);

    if (rc != 1) {
        aws_cryptosdk_secure_zero(buf, len);
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    return AWS_OP_SUCCESS;
}
