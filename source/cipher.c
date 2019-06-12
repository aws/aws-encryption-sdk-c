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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdbool.h>

#include <aws/common/byte_order.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/hkdf.h>

#define MSG_ID_LEN 16

const struct aws_cryptosdk_alg_properties *aws_cryptosdk_alg_props(enum aws_cryptosdk_alg_id alg_id) {
#define EVP_NULL NULL
#define STATIC_ALG_PROPS(alg_id_v, md, cipher, dk_len_v, iv_len_v, tag_len_v, signature_len_v, curve_name_v)   \
    case alg_id_v: {                                                                                           \
        static const struct aws_cryptosdk_alg_impl impl = {                                                    \
            .md_ctor     = (EVP_##md),                                                                         \
            .cipher_ctor = (EVP_##cipher),                                                                     \
            .curve_name  = (curve_name_v),                                                                     \
        };                                                                                                     \
        static const struct aws_cryptosdk_alg_properties props = {                                             \
            .md_name     = #md,                                                                                \
            .cipher_name = #cipher,                                                                            \
            .alg_name    = #alg_id_v,                                                                          \
            .impl        = &impl,                                                                              \
            .data_key_len =                                                                                    \
                (dk_len_v) / 8, /* Currently we don't support any algorithms where DK and CK lengths differ */ \
            .content_key_len = (dk_len_v) / 8,                                                                 \
            .iv_len          = (iv_len_v),                                                                     \
            .tag_len         = (tag_len_v),                                                                    \
            .alg_id          = (alg_id_v),                                                                     \
            .signature_len   = (signature_len_v)                                                               \
        };                                                                                                     \
        return &props;                                                                                         \
    }
    switch (alg_id) {
        STATIC_ALG_PROPS(ALG_AES128_GCM_IV12_TAG16_NO_KDF, NULL, aes_128_gcm, 128, 12, 16, 0, NULL);
        STATIC_ALG_PROPS(ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256, sha256, aes_128_gcm, 128, 12, 16, 0, NULL);
        STATIC_ALG_PROPS(ALG_AES192_GCM_IV12_TAG16_NO_KDF, NULL, aes_192_gcm, 192, 12, 16, 0, NULL);
        STATIC_ALG_PROPS(ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256, sha256, aes_192_gcm, 192, 12, 16, 0, NULL);
        STATIC_ALG_PROPS(ALG_AES256_GCM_IV12_TAG16_NO_KDF, NULL, aes_256_gcm, 256, 12, 16, 0, NULL);
        STATIC_ALG_PROPS(ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256, sha256, aes_256_gcm, 256, 12, 16, 0, NULL);
        // secp256r1 aka prime256v1 aka P-256
        // openssl does not define the 'secp256r1' alias however
        STATIC_ALG_PROPS(
            ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, sha256, aes_128_gcm, 128, 12, 16, 71, "prime256v1");
        STATIC_ALG_PROPS(
            ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, sha384, aes_192_gcm, 192, 12, 16, 103, "secp384r1");
        STATIC_ALG_PROPS(
            ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, sha384, aes_256_gcm, 256, 12, 16, 103, "secp384r1");
        default: return NULL;
    }
#undef STATIC_ALG_PROPS
#undef EVP_NULL
}

static enum aws_cryptosdk_sha_version aws_cryptosdk_which_sha(enum aws_cryptosdk_alg_id alg_id) {
    switch (alg_id) {
        case ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
        case ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384: return AWS_CRYPTOSDK_SHA384;
        case ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
        case ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256:
        case ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256:
        case ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256: return AWS_CRYPTOSDK_SHA256;
        case ALG_AES256_GCM_IV12_TAG16_NO_KDF:
        case ALG_AES192_GCM_IV12_TAG16_NO_KDF:
        case ALG_AES128_GCM_IV12_TAG16_NO_KDF:
        default: return AWS_CRYPTOSDK_NOSHA;
    }
}

static bool alg_properties_equal(
    const struct aws_cryptosdk_alg_properties alg_props1, const struct aws_cryptosdk_alg_properties alg_props2) {
    /* Note: We are not checking whether the names (md/cipher/alg) are
     * equal */

    /* Note: We are not checking whether the underlying alg_impl
     * structs are equal. */
    return alg_props1.data_key_len == alg_props2.data_key_len &&
           alg_props1.content_key_len == alg_props2.content_key_len && alg_props1.iv_len == alg_props2.iv_len &&
           alg_props1.tag_len == alg_props2.tag_len && alg_props1.signature_len == alg_props2.signature_len &&
           alg_props1.alg_id == alg_props2.alg_id;
}

bool aws_cryptosdk_alg_properties_is_valid(const struct aws_cryptosdk_alg_properties *const alg_props) {
    if (alg_props == NULL) {
        return false;
    }
    enum aws_cryptosdk_alg_id id                             = alg_props->alg_id;
    const struct aws_cryptosdk_alg_properties *std_alg_props = aws_cryptosdk_alg_props(id);
    if (std_alg_props == NULL) {
        return false;
    }
    return alg_props->md_name && alg_props->cipher_name && alg_props->alg_name &&
           alg_properties_equal(*alg_props, *std_alg_props);
}

int aws_cryptosdk_derive_key(
    const struct aws_cryptosdk_alg_properties *props,
    struct content_key *content_key,
    const struct data_key *data_key,
    const uint8_t *message_id) {
    aws_secure_zero(content_key->keybuf, sizeof(content_key->keybuf));
    uint8_t info[MSG_ID_LEN + 2];
    uint16_t alg_id = props->alg_id;
    info[0]         = alg_id >> 8;
    info[1]         = alg_id & 0xFF;
    memcpy(&info[2], message_id, sizeof(info) - 2);
    enum aws_cryptosdk_sha_version which_sha = aws_cryptosdk_which_sha(props->alg_id);
    if (which_sha == AWS_CRYPTOSDK_NOSHA) {
        memcpy(content_key->keybuf, data_key->keybuf, props->data_key_len);
        return AWS_OP_SUCCESS;
    }
    struct aws_byte_buf myokm        = aws_byte_buf_from_array(content_key->keybuf, props->content_key_len);
    const struct aws_byte_buf mysalt = aws_byte_buf_from_c_str("");
    const struct aws_byte_buf myikm  = aws_byte_buf_from_array(data_key->keybuf, props->data_key_len);
    const struct aws_byte_buf myinfo = aws_byte_buf_from_array(info, MSG_ID_LEN + 2);
    return aws_cryptosdk_hkdf(&myokm, which_sha, &mysalt, &myikm, &myinfo);
}

static EVP_CIPHER_CTX *evp_gcm_cipher_init(
    const struct aws_cryptosdk_alg_properties *props,
    const struct content_key *content_key,
    const uint8_t *iv,
    bool enc) {
    EVP_CIPHER_CTX *ctx = NULL;

    if (!(ctx = EVP_CIPHER_CTX_new())) goto err;
    if (!EVP_CipherInit_ex(ctx, props->impl->cipher_ctor(), NULL, NULL, NULL, enc)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, props->iv_len, NULL)) goto err;
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, content_key->keybuf, iv, -1)) goto err;

    return ctx;

err:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return NULL;
}

static int evp_gcm_encrypt_final(const struct aws_cryptosdk_alg_properties *props, EVP_CIPHER_CTX *ctx, uint8_t *tag) {
    int outlen;
    uint8_t finalbuf;

    if (!EVP_EncryptFinal_ex(ctx, &finalbuf, &outlen)) {
        return AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    }

    if (outlen != 0) {
        abort();  // wrong output size - potentially smashed stack
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, props->tag_len, (void *)tag)) {
        return AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    }

    return AWS_ERROR_SUCCESS;
}

static inline void flush_openssl_errors() {
    while (ERR_get_error() != 0) {
    }
}

static int evp_gcm_decrypt_final(
    const struct aws_cryptosdk_alg_properties *props, EVP_CIPHER_CTX *ctx, const uint8_t *tag) {
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, props->tag_len, (void *)tag)) {
        return AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    }

    /*
     * Flush all error codes; if the GCM tag is invalid, openssl will fail without generating
     * an error code, so any leftover error codes will get in the way of detection.
     */
    flush_openssl_errors();

    int outlen;
    uint8_t finalbuf;

    if (!EVP_DecryptFinal_ex(ctx, &finalbuf, &outlen)) {
        if (ERR_peek_last_error() == 0) {
            return AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT;
        }
        return AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    }

    if (outlen != 0) {
        abort();  // wrong output size - potentially smashed stack
    }

    return AWS_ERROR_SUCCESS;
}

int aws_cryptosdk_sign_header(
    const struct aws_cryptosdk_alg_properties *props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header) {
    if (authtag->len != props->iv_len + props->tag_len) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    uint8_t *iv  = authtag->buffer;
    uint8_t *tag = authtag->buffer + props->iv_len;

    /*
     * Currently, we use a deterministic IV generation algorithm;
     * the header IV is always all-zero.
     */
    aws_secure_zero(iv, props->iv_len);

    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    EVP_CIPHER_CTX *ctx = evp_gcm_cipher_init(props, content_key, iv, true);
    if (!ctx) goto out;

    int outlen;
    if (!EVP_CipherUpdate(ctx, NULL, &outlen, header->buffer, header->len)) goto out;

    result = evp_gcm_encrypt_final(props, ctx, tag);
out:
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    if (result == AWS_ERROR_SUCCESS) {
        return AWS_OP_SUCCESS;
    } else {
        return aws_raise_error(result);
    }
}

int aws_cryptosdk_verify_header(
    const struct aws_cryptosdk_alg_properties *props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header) {
    /*
     * Note: We don't delegate to sign_header here, as we want to leave the
     * GCM tag comparison (which needs to be constant-time) to openssl.
     */

    if (authtag->len != props->iv_len + props->tag_len) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    const uint8_t *iv  = authtag->buffer;
    const uint8_t *tag = authtag->buffer + props->iv_len;
    int result         = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    EVP_CIPHER_CTX *ctx = evp_gcm_cipher_init(props, content_key, iv, false);
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
    EVP_CIPHER_CTX *ctx, const uint8_t *message_id, int body_frame_type, uint32_t seqno, uint64_t data_size) {
    const char *aad_string;

    switch (body_frame_type) {
        case FRAME_TYPE_SINGLE: aad_string = "AWSKMSEncryptionClient Single Block"; break;
        case FRAME_TYPE_FRAME: aad_string = "AWSKMSEncryptionClient Frame"; break;
        case FRAME_TYPE_FINAL: aad_string = "AWSKMSEncryptionClient Final Frame"; break;
        default: return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    int ignored;

    if (!EVP_CipherUpdate(ctx, NULL, &ignored, message_id, MSG_ID_LEN)) return 0;
    if (!EVP_CipherUpdate(ctx, NULL, &ignored, (const uint8_t *)aad_string, strlen(aad_string))) return 0;

    seqno = aws_hton32(seqno);
    if (!EVP_CipherUpdate(ctx, NULL, &ignored, (const uint8_t *)&seqno, sizeof(seqno))) return 0;

    uint32_t size[2];

    size[0] = aws_hton32(data_size >> 32);
    size[1] = aws_hton32(data_size & 0xFFFFFFFFUL);

    return EVP_CipherUpdate(ctx, NULL, &ignored, (const uint8_t *)size, sizeof(size));
}

int aws_cryptosdk_encrypt_body(
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_buf *outp,
    const struct aws_byte_cursor *inp,
    const uint8_t *message_id,
    uint32_t seqno,
    uint8_t *iv,
    const struct content_key *key,
    uint8_t *tag,
    int body_frame_type) {
    if (inp->len != outp->capacity) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    /*
     * We use a deterministic IV generation algorithm; the frame sequence number
     * is used for the IV. To avoid collisions with the header IV, seqno=0 is
     * forbidden.
     */
    if (seqno == 0) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    uint64_t iv_seq = aws_hton64(seqno);

    /*
     * Paranoid check to make sure we're not going to walk off the end of the IV
     * buffer if someone in the future introduces an algorithm with a really small
     * IV for some reason.
     */
    if (props->iv_len < sizeof(iv_seq)) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    aws_secure_zero(iv, props->iv_len);

    uint8_t *iv_seq_p = iv + props->iv_len - sizeof(iv_seq);
    memcpy(iv_seq_p, &iv_seq, sizeof(iv_seq));

    EVP_CIPHER_CTX *ctx = NULL;

    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    if (!(ctx = evp_gcm_cipher_init(props, key, iv, true))) goto out;
    if (!update_frame_aad(ctx, message_id, body_frame_type, seqno, inp->len)) goto out;

    struct aws_byte_buf outbuf    = *outp;
    struct aws_byte_cursor incurs = *inp;

    while (incurs.len) {
        if (incurs.len != outbuf.capacity - outbuf.len) {
            /*
             * None of the algorithms we currently support should break this invariant.
             * Bail out immediately with an unknown error.
             */
            goto out;
        }

        int in_len = incurs.len > INT_MAX ? INT_MAX : incurs.len;
        int ct_len;

        if (!EVP_EncryptUpdate(ctx, outbuf.buffer + outbuf.len, &ct_len, incurs.ptr, in_len)) goto out;
        /*
         * The next two advances should never fail ... but check the return values
         * just in case.
         */
        if (!aws_byte_cursor_advance_nospec(&incurs, in_len).ptr) goto out;
        outbuf.len += ct_len;

        if (outbuf.capacity < outbuf.len) {
            /* Somehow we ran over the output buffer. abort() to limit the damage. */
            abort();
        }
    }

    result = evp_gcm_encrypt_final(props, ctx, tag);

out:
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    if (result == AWS_ERROR_SUCCESS) {
        *outp = outbuf;
        return AWS_OP_SUCCESS;
    } else {
        aws_byte_buf_secure_zero(outp);
        return aws_raise_error(result);
    }
}

int aws_cryptosdk_decrypt_body(
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_buf *outp,
    const struct aws_byte_cursor *inp,
    const uint8_t *message_id,
    uint32_t seqno,
    const uint8_t *iv,
    const struct content_key *key,
    const uint8_t *tag,
    int body_frame_type) {
    if (inp->len != outp->capacity - outp->len) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    EVP_CIPHER_CTX *ctx           = NULL;
    struct aws_byte_buf outcurs   = *outp;
    struct aws_byte_cursor incurs = *inp;
    int result                    = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    if (!(ctx = evp_gcm_cipher_init(props, key, iv, false))) goto out;

    if (!update_frame_aad(ctx, message_id, body_frame_type, seqno, inp->len)) goto out;

    while (incurs.len) {
        int in_len = incurs.len > INT_MAX ? INT_MAX : incurs.len;
        int pt_len;

        if (!EVP_DecryptUpdate(ctx, outcurs.buffer + outcurs.len, &pt_len, incurs.ptr, in_len)) goto out;
        /*
         * The next two advances should never fail ... but check the return values
         * just in case.
         */
        if (!aws_byte_cursor_advance_nospec(&incurs, in_len).ptr) goto out;
        outcurs.len += pt_len;
        if (outcurs.len > outcurs.capacity) {
            /* Somehow we ran over the output buffer. abort() to limit the damage. */
            abort();
        }
    }

    result = evp_gcm_decrypt_final(props, ctx, tag);
out:
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    if (result == AWS_ERROR_SUCCESS) {
        *outp = outcurs;
        return AWS_OP_SUCCESS;
    } else {
        aws_byte_buf_secure_zero(outp);
        return aws_raise_error(result);
    }
}

int aws_cryptosdk_genrandom(uint8_t *buf, size_t len) {
    int rc = RAND_bytes(buf, len);

    if (rc != 1) {
        aws_secure_zero(buf, len);
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    return AWS_OP_SUCCESS;
}

static const EVP_CIPHER *get_alg_from_key_size(size_t key_len) {
    switch (key_len) {
        case AWS_CRYPTOSDK_AES128: return EVP_aes_128_gcm();
        case AWS_CRYPTOSDK_AES192: return EVP_aes_192_gcm();
        case AWS_CRYPTOSDK_AES256: return EVP_aes_256_gcm();
        default: return NULL;
    }
}

// These implementations of AES-GCM encryption/decryption only support these tag/IV lengths
static const size_t aes_gcm_tag_len = 16;
static const size_t aes_gcm_iv_len  = 12;

int aws_cryptosdk_aes_gcm_encrypt(
    struct aws_byte_buf *cipher,
    struct aws_byte_buf *tag,
    const struct aws_byte_cursor plain,
    const struct aws_byte_cursor iv,
    const struct aws_byte_cursor aad,
    const struct aws_string *key) {
    const EVP_CIPHER *alg = get_alg_from_key_size(key->len);
    if (!alg || iv.len != aes_gcm_iv_len || tag->capacity < aes_gcm_tag_len || cipher->capacity < plain.len)
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto openssl_err;

    if (!EVP_EncryptInit_ex(ctx, alg, NULL, aws_string_bytes(key), iv.ptr)) goto openssl_err;

    int out_len;
    if (!EVP_EncryptUpdate(ctx, NULL, &out_len, aad.ptr, aad.len)) goto openssl_err;

    if (!EVP_EncryptUpdate(ctx, cipher->buffer, &out_len, plain.ptr, plain.len)) goto openssl_err;
    int prev_len = out_len;

    if (!EVP_EncryptFinal_ex(ctx, cipher->buffer + out_len, &out_len)) goto openssl_err;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, aes_gcm_tag_len, tag->buffer)) goto openssl_err;

    tag->len    = aes_gcm_tag_len;
    cipher->len = prev_len + out_len;
    assert(cipher->len == plain.len);
    EVP_CIPHER_CTX_free(ctx);
    return AWS_OP_SUCCESS;

openssl_err:
    EVP_CIPHER_CTX_free(ctx);
    aws_byte_buf_secure_zero(cipher);
    aws_byte_buf_secure_zero(tag);
    flush_openssl_errors();
    return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
}

int aws_cryptosdk_aes_gcm_decrypt(
    struct aws_byte_buf *plain,
    const struct aws_byte_cursor cipher,
    const struct aws_byte_cursor tag,
    const struct aws_byte_cursor iv,
    const struct aws_byte_cursor aad,
    const struct aws_string *key) {
    bool openssl_err      = true;
    const EVP_CIPHER *alg = get_alg_from_key_size(key->len);
    if (!alg || iv.len != aes_gcm_iv_len || tag.len != aes_gcm_tag_len || plain->capacity < cipher.len)
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto decrypt_err;

    if (!EVP_DecryptInit_ex(ctx, alg, NULL, aws_string_bytes(key), iv.ptr)) goto decrypt_err;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.len, tag.ptr)) goto decrypt_err;

    /* Setting the AAD. out_len here is a throwaway. Might be able to make that argument NULL, but
     * openssl wiki example does the same as this, giving it a pointer to an int and disregarding value.
     */
    int out_len;
    if (!EVP_DecryptUpdate(ctx, NULL, &out_len, aad.ptr, aad.len)) goto decrypt_err;

    if (!EVP_DecryptUpdate(ctx, plain->buffer, &out_len, cipher.ptr, cipher.len)) goto decrypt_err;
    int prev_len = out_len;

    /* Possible for EVP_DecryptFinal_ex to fail without generating an OpenSSL error code (e.g., tag
     * mismatch) so flush the errors first to distinguish this case.
     */
    flush_openssl_errors();
    if (!EVP_DecryptFinal_ex(ctx, plain->buffer + out_len, &out_len)) {
        if (!ERR_peek_last_error()) openssl_err = false;
        goto decrypt_err;
    }
    EVP_CIPHER_CTX_free(ctx);
    plain->len = prev_len + out_len;
    assert(plain->len == cipher.len);
    return AWS_OP_SUCCESS;

decrypt_err:
    EVP_CIPHER_CTX_free(ctx);
    aws_byte_buf_secure_zero(plain);  // sets plain->len to zero
    if (openssl_err) {
        flush_openssl_errors();
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }
    return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
}

static int get_openssl_rsa_padding_mode(enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode) {
    switch (rsa_padding_mode) {
        case AWS_CRYPTOSDK_RSA_PKCS1: return RSA_PKCS1_PADDING;
        case AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1: return RSA_PKCS1_OAEP_PADDING;
        case AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1: return RSA_PKCS1_OAEP_PADDING;
        default: return -1;
    }
}

int aws_cryptosdk_rsa_encrypt(
    struct aws_byte_buf *cipher,
    struct aws_allocator *alloc,
    const struct aws_byte_cursor plain,
    const struct aws_string *rsa_public_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode) {
    if (cipher->buffer) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    int padding = get_openssl_rsa_padding_mode(rsa_padding_mode);
    if (padding < 0) return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
    BIO *bio          = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey    = NULL;
    bool error        = true;
    int err_code      = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    pkey              = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    bio = BIO_new_mem_buf(aws_string_bytes(rsa_public_key_pem), rsa_public_key_pem->len);
    if (!bio) goto cleanup;
    if (!PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)) goto cleanup;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) goto cleanup;
    if (rsa_padding_mode == AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto cleanup;
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto cleanup;
    }
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plain.ptr, plain.len) <= 0) goto cleanup;
    if (aws_byte_buf_init(cipher, alloc, outlen)) goto cleanup;
    if (1 == EVP_PKEY_encrypt(ctx, cipher->buffer, &outlen, plain.ptr, plain.len)) {
        cipher->len = outlen;
        error       = false;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    flush_openssl_errors();
    if (error) {
        aws_byte_buf_clean_up_secure(cipher);
        return aws_raise_error(err_code);
    } else {
        return AWS_OP_SUCCESS;
    }
}

int aws_cryptosdk_rsa_decrypt(
    struct aws_byte_buf *plain,
    struct aws_allocator *alloc,
    const struct aws_byte_cursor cipher,
    const struct aws_string *rsa_private_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode) {
    if (plain->buffer) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    int padding = get_openssl_rsa_padding_mode(rsa_padding_mode);
    if (padding < 0) return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
    BIO *bio          = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey    = NULL;
    bool error        = true;
    int err_code      = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;
    pkey              = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    bio = BIO_new_mem_buf(aws_string_bytes(rsa_private_key_pem), rsa_private_key_pem->len);
    if (!bio) goto cleanup;
    if (!PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)) goto cleanup;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) goto cleanup;
    if (rsa_padding_mode == AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto cleanup;
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto cleanup;
    }
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, cipher.ptr, cipher.len) <= 0) goto cleanup;
    if (aws_byte_buf_init(plain, alloc, outlen)) goto cleanup;
    if (EVP_PKEY_decrypt(ctx, plain->buffer, &outlen, cipher.ptr, cipher.len) <= 0) {
        err_code = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT;
    } else {
        plain->len = outlen;
        error      = false;
    }

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    flush_openssl_errors();
    if (error) {
        aws_byte_buf_clean_up_secure(plain);
        return aws_raise_error(err_code);
    } else {
        return AWS_OP_SUCCESS;
    }
}
