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

#include "proof_helpers.h"
#include <openssl/evp.h>
#include <aws/cryptosdk/private/cipher.h>

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

int aws_cryptosdk_sign_header_verify(
    const struct aws_cryptosdk_alg_properties *props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header
) {
    ASSUME_VALID_MEMORY(content_key);

    aws_cryptosdk_sign_header(props, content_key, authtag, header);
}

int aws_cryptosdk_verify_header_verify(
    const struct aws_cryptosdk_alg_properties *props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header
) {
    ASSUME_VALID_MEMORY(content_key);

    aws_cryptosdk_verify_header(props, content_key, authtag, header);
}

int aws_cryptosdk_encrypt_body_verify(
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_cursor *outp,
    const struct aws_byte_cursor *inp,
    const uint8_t *message_id,
    uint32_t seqno,
    uint8_t *iv,
    const struct content_key *key,
    uint8_t *tag,
    int body_frame_type
) {

    aws_cryptosdk_encrypt_body(props, outp, inp, message_id, seqno, iv, key, tag, body_frame_type);
}


int aws_cryptosdk_decrypt_body_verify(
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_cursor *outp,
    const struct aws_byte_cursor *inp,
    const uint8_t *message_id,
    uint32_t seqno,
    const uint8_t *iv,
    const struct content_key *key,
    const uint8_t *tag,
    int body_frame_type
) {

    aws_cryptosdk_decrypt_body(props, outp, inp, message_id, seqno, iv, key, tag, body_frame_type);
}


// NOTE: internal assert(plain->len == cipher.len) fails

int aws_cryptosdk_aes_gcm_encrypt_verify(struct aws_byte_buf * cipher,
                                  struct aws_byte_buf * tag,
                                  const struct aws_byte_cursor plain,
                                  const struct aws_byte_cursor iv,
                                  const struct aws_byte_cursor aad,
                                  const struct aws_string * key) {

    aws_cryptosdk_aes_gcm_encrypt(cipher, tag, plain, iv, aad, key);

}

// NOTE: internal assert(plain->len == cipher.len) fails

int aws_cryptosdk_aes_gcm_decrypt_verify(struct aws_byte_buf * plain,
                                  const struct aws_byte_cursor cipher,
                                  const struct aws_byte_cursor tag,
                                  const struct aws_byte_cursor iv,
                                  const struct aws_byte_cursor aad,
                                  const struct aws_string * key) {

    aws_cryptosdk_aes_gcm_decrypt(plain, cipher, tag, iv, aad, key);

}