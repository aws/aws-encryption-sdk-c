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

#ifndef AWS_CRYPTOSDK_PRIVATE_CIPHER_H
#define AWS_CRYPTOSDK_PRIVATE_CIPHER_H

#include <aws/cryptosdk/cipher.h>
#include <openssl/evp.h>

/*
 * TODO - Finish splitting cipher.c into common code and backend, and move this into the backends.
 */
struct aws_cryptosdk_alg_impl {
    const EVP_MD *(*md_ctor)(void);
    const EVP_CIPHER *(*cipher_ctor)(void);
    const char *curve_name;
};

/**
 * Internal cryptographic helpers.
 * This header is not installed and is not a stable API.
 */

#define MAX_DATA_KEY_SIZE 32

struct data_key {
    uint8_t keybuf[MAX_DATA_KEY_SIZE];
};

struct content_key {
    uint8_t keybuf[MAX_DATA_KEY_SIZE];
};

/**
 * Derive the decryption key from the data key.
 * Depending on the algorithm ID, this either does a HKDF,
 * or a no-op copy of the key.
 */
int aws_cryptosdk_derive_key(
    const struct aws_cryptosdk_alg_properties *alg_props,
    struct content_key *content_key,
    const struct data_key *data_key,
    const uint8_t *message_id
);

/**
 * Verifies the header authentication tag.
 * Returns AWS_OP_SUCCESS if the tag is valid, raises AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT
 * if invalid.
 */
int aws_cryptosdk_verify_header(
    const struct aws_cryptosdk_alg_properties *alg_props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header
);

/**
 * Computes the header authentication tag. The tag (and IV) is written to the authtag buffer.
 */
int aws_cryptosdk_sign_header(
    const struct aws_cryptosdk_alg_properties *alg_props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header
);


enum aws_cryptosdk_frame_type {
    FRAME_TYPE_SINGLE,
    FRAME_TYPE_FRAME,
    FRAME_TYPE_FINAL
};

// TODO: Initialize the cipher once and reuse it
/**
 * Decrypts either the body of the message (for non-framed messages) or a single frame of the message.
 * Returns AWS_OP_SUCCESS if successful.
 */
int aws_cryptosdk_decrypt_body(
    const struct aws_cryptosdk_alg_properties *alg_props,
    struct aws_byte_cursor *out,
    const struct aws_byte_cursor *in,
    const uint8_t *message_id,
    uint32_t seqno,
    const uint8_t *iv,
    const struct content_key *key,
    const uint8_t *tag,
    int body_frame_type
);

/**
 * Encrypts either the body of the message (for non-framed messages) or a single frame of the message.
 * Returns AWS_OP_SUCCESS if successful.
 */
int aws_cryptosdk_encrypt_body(
    const struct aws_cryptosdk_alg_properties *alg_props,
    struct aws_byte_cursor *out,
    const struct aws_byte_cursor *in,
    const uint8_t *message_id,
    uint32_t seqno,
    uint8_t *iv, /* out */
    const struct content_key *key,
    uint8_t *tag, /* out */
    int body_frame_type
);


int aws_cryptosdk_genrandom(
    uint8_t *buf,
    size_t len
);

// TODO: Footer

/**
 * Does AES-GCM encryption using AES-256/192/128 with 12 byte IVs and 16 byte tags only.
 * Determines which AES algorithm to use based on length of key.
 *
 * Assumes cipher and tag are already allocated byte buffers. Does NOT assume that lengths
 * of buffers are already set, and will set them on successful encrypt.
 *
 * Returns AWS_OP_SUCCESS on a successful encrypt. On failure, returns AWS_OP_ERR and sets
 * one of the following error codes:
 *
 * AWS_INVALID_BUFFER_SIZE : bad key or IV length, or not enough capacity in output buffers
 * AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN : OpenSSL error
 *
 * On last error, output buffers will be set to all zero bytes, and their lengths will be
 * set to zero.
 */
int aws_cryptosdk_aes_gcm_encrypt(struct aws_byte_buf * cipher,
                                  struct aws_byte_buf * tag,
                                  const struct aws_byte_cursor plain,
                                  const struct aws_byte_cursor iv,
                                  const struct aws_byte_cursor aad,
                                  const struct aws_string * key);

/**
 * Does AES-GCM decryption using AES-256/192/128 with 12 byte IVs and 16 byte tags only.
 * Determines which AES algorithm to use based on length of key.
 *
 * Assumes plain is an already allocated byte buffer. Does NOT assume that length of plain
 * buffer is already set, and will set it to the length of plain on a successful decrypt.
 *
 * Returns AWS_OP_SUCCESS on a successful decrypt. On failure, returns AWS_OP_ERR and sets
 * one of the following error codes:
 *
 * AWS_INVALID_BUFFER_SIZE : bad key, tag, or IV length, or not enough capacity in plain
 * AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT : unable to decrypt or authenticate ciphertext
 * AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN : OpenSSL error
 *
 * On either of the last two errors, the plain buffer will be set to all zero bytes, and its
 * length will be set to zero.
 */
int aws_cryptosdk_aes_gcm_decrypt(struct aws_byte_buf * plain,
                                  const struct aws_byte_cursor cipher,
                                  const struct aws_byte_cursor tag,
                                  const struct aws_byte_cursor iv,
                                  const struct aws_byte_cursor aad,
                                  const struct aws_string * key);


/**
 * A structure representing an ongoing sign or verify operation
 */
struct aws_cryptosdk_signctx;

/**
 * Obtains the private key from a signing context, and serializes it to a byte buffer.
 * The serialization format is not currently guaranteed to remain unchanged.
 *
 * This method is intended to be used with caching mechanisms to clone the signing context.
 */
int aws_cryptosdk_sig_get_privkey(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx *ctx,
    struct aws_byte_buf *priv_key_buf
);

/**
 * Generates a new signature keypair, initializes a signing context, and serializes the public key.
 * If a non-signing algorithm is used, this function returns successfully, and sets *ctx to NULL.
 *
 * @param alloc - the allocator to use
 * @param pctx - a pointer to a variable to receive the context pointer
 * @param props - The algorithm properties for the algorithm to use
 * @param pub_key_buf - A buffer that will receive the public key (in base64 format).
 *   This buffer will be allocated as part of this call, and does not need to be pre-initialized.
 */
int aws_cryptosdk_sig_keygen(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx **pctx,
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_buf *pub_key_buf
);

/**
 * Initializes a new signature context based on a private key serialized using
 * aws_cryptosdk_sig_get_privkey.
 *
 * @param
 *   alloc - the allocator to use
 *   ctx   - a pointer to a variable to receive the signing context
 *   pub_key_buf - a pointer to a buffer that will receive the base-64 public key,
 *     or NULL if not required
 *   props - algorithm properties for the algorithm suite in use
 *   priv_key - the previously serialized private key
 */
int aws_cryptosdk_sig_sign_start(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx **ctx,
    struct aws_byte_buf *pub_key_buf,
    const struct aws_cryptosdk_alg_properties *props,
    const struct aws_byte_buf *priv_key
);

/**
 * Prepares to validate a signature.
 * If a non-signing algorithm is used, this function returns successfully, and sets *ctx to NULL.
 *
 * @param alloc - the allocator to use
 * @param pctx - a pointer to a variable to receive the context pointer
 * @param props - The algorithm properties for the algorithm to use
 * @param pub_key - A buffer containing the (base64) public key
 */
int aws_cryptosdk_sig_verify_start(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx **pctx,
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_byte_buf *pub_key
);

/**
 * Supplies some data to an ongoing sign or verify operation
 */
int aws_cryptosdk_sig_update(
    struct aws_cryptosdk_signctx *ctx,
    const struct aws_byte_buf *buf
);

/**
 * Verifies a signature against the data previously passed to aws_cryptosdk_sig_update.
 * If successful, this function returns AWS_OP_SUCCESS; if the signature was invalid,
 * raises AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT and returns AWS_OP_ERR.
 *
 * The context is always freed, regardless of success or failure.
 */
int aws_cryptosdk_sig_verify_finish(
    struct aws_cryptosdk_signctx *ctx,
    const struct aws_byte_buf *signature
);

/**
 * Generates the final signature based on data previously passed to aws_cryptosdk_sig_update.
 * The signature buffer will be allocated using 'alloc'.
 *
 * The context is always freed, regardless of success or failure.
 */
int aws_cryptosdk_sig_sign_finish(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_signctx *ctx,
    struct aws_byte_buf *signature
);

/**
 * Aborts an ongoing sign or verify operation, and destroys the signature context.
 */
void aws_cryptosdk_sig_abort(
    struct aws_cryptosdk_signctx *ctx
);
#endif // AWS_CRYPTOSDK_PRIVATE_CIPHER_H
