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

struct aws_cryptosdk_md_context;

#define AWS_CRYPTOSDK_MD_MAX_SIZE (512 / 8)

enum aws_cryptosdk_md_alg { AWS_CRYPTOSDK_MD_SHA512 };

bool aws_cryptosdk_md_context_is_valid(const struct aws_cryptosdk_md_context *md_context);

int aws_cryptosdk_md_init(
    struct aws_allocator *alloc, struct aws_cryptosdk_md_context **md_context, enum aws_cryptosdk_md_alg md_alg);

size_t aws_cryptosdk_md_size(enum aws_cryptosdk_md_alg alg);

int aws_cryptosdk_md_update(struct aws_cryptosdk_md_context *md_context, const void *buf, size_t length);

int aws_cryptosdk_md_finish(struct aws_cryptosdk_md_context *md_context, void *output_buf, size_t *length);

void aws_cryptosdk_md_abort(struct aws_cryptosdk_md_context *md_context);

/**
 * Derive the decryption key from the data key.
 * Depending on the algorithm ID, this either does a HKDF,
 * or a no-op copy of the key.
 */
int aws_cryptosdk_derive_key(
    const struct aws_cryptosdk_alg_properties *alg_props,
    struct content_key *content_key,
    const struct data_key *data_key,
    const uint8_t *message_id);

/**
 * Verifies the header authentication tag.
 * Returns AWS_OP_SUCCESS if the tag is valid, raises AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT
 * if invalid.
 */
int aws_cryptosdk_verify_header(
    const struct aws_cryptosdk_alg_properties *alg_props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header);

/**
 * Computes the header authentication tag. The tag (and IV) is written to the authtag buffer.
 */
int aws_cryptosdk_sign_header(
    const struct aws_cryptosdk_alg_properties *alg_props,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header);

enum aws_cryptosdk_frame_type { FRAME_TYPE_SINGLE, FRAME_TYPE_FRAME, FRAME_TYPE_FINAL };

// TODO: Initialize the cipher once and reuse it
/**
 * Decrypts either the body of the message (for non-framed messages) or a single frame of the message.
 * Returns AWS_OP_SUCCESS if successful.
 */
int aws_cryptosdk_decrypt_body(
    const struct aws_cryptosdk_alg_properties *alg_props,
    struct aws_byte_buf *out,
    const struct aws_byte_cursor *in,
    const uint8_t *message_id,
    uint32_t seqno,
    const uint8_t *iv,
    const struct content_key *key,
    const uint8_t *tag,
    int body_frame_type);

/**
 * Encrypts either the body of the message (for non-framed messages) or a single frame of the message.
 * Returns AWS_OP_SUCCESS if successful.
 */
int aws_cryptosdk_encrypt_body(
    const struct aws_cryptosdk_alg_properties *alg_props,
    struct aws_byte_buf *out,
    const struct aws_byte_cursor *in,
    const uint8_t *message_id,
    uint32_t seqno,
    uint8_t *iv, /* out */
    const struct content_key *key,
    uint8_t *tag, /* out */
    int body_frame_type);

int aws_cryptosdk_genrandom(uint8_t *buf, size_t len);

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
int aws_cryptosdk_aes_gcm_encrypt(
    struct aws_byte_buf *cipher,
    struct aws_byte_buf *tag,
    const struct aws_byte_cursor plain,
    const struct aws_byte_cursor iv,
    const struct aws_byte_cursor aad,
    const struct aws_string *key);

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
int aws_cryptosdk_aes_gcm_decrypt(
    struct aws_byte_buf *plain,
    const struct aws_byte_cursor cipher,
    const struct aws_byte_cursor tag,
    const struct aws_byte_cursor iv,
    const struct aws_byte_cursor aad,
    const struct aws_string *key);

/**
 * Does RSA decryption of an encrypted data key to an unecrypted data key.
 * RSA with PKCS1, OAEP_SHA1_MGF1 and OAEP_SHA256_MGF1 padding modes is supported.
 *
 * Here, 'plain' refers to the unencrypted AES data key obtained as a result of the RSA
 * decryption, 'rsa_private_key_pem' is a string that contains the RSA private key in PEM
 * format and 'cipher' is the encrypted AES data key.
 *
 * This function requires that plain has no memory allocated to it already, and allocates
 * it newly. The length of the buffer will be set to the length of plain on a successful decrypt.
 *
 * Returns AWS_OP_SUCCESS on a successful decrypt. On failure, returns AWS_OP_ERR and sets
 * one of the following error codes:
 *
 * AWS_CRYPTOSDK_ERR_BAD_STATE : the output buffer was not in the proper (unallocated) state
 * AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT: unsupported padding mode for RSA wrapping algorithm
 * AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT : unable to decrypt or authenticate cipher text
 * AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN : OpenSSL error
 */
int aws_cryptosdk_rsa_decrypt(
    struct aws_byte_buf *plain,
    struct aws_allocator *alloc,
    const struct aws_byte_cursor cipher,
    const struct aws_string *rsa_private_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

/**
 * Does RSA encryption of an unencrypted data key to an encrypted data key.
 * RSA with PKCS1, OAEP_SHA1_MGF1 and OAEP_SHA256_MGF1 padding modes is supported.
 *
 * Here, 'cipher' is the encrypted AES data key obtained as a result of the RSA encryption,
 *'rsa_public_key_pem' is a string that contains the RSA public key in PEM format and 'plain'
 * refers to the unencrypted AES data key.
 *
 * This function requires that cipher has no memory allocated to it already, and allocates
 * it newly. The length of the buffer will be set to the length of cipher on a successful encrypt.
 *
 * Returns AWS_OP_SUCCESS on a successful encrypt. On failure, returns AWS_OP_ERR and sets
 * one of the following error codes:
 *
 * AWS_CRYPTOSDK_ERR_BAD_STATE : the output buffer was not in the proper (unallocated) state
 * AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT: unsupported padding mode for RSA wrapping algorithm
 * AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN : OpenSSL error or other unknown errors
 */
int aws_cryptosdk_rsa_encrypt(
    struct aws_byte_buf *cipher,
    struct aws_allocator *alloc,
    const struct aws_byte_cursor plain,
    const struct aws_string *rsa_public_key_pem,
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

#endif  // AWS_CRYPTOSDK_PRIVATE_CIPHER_H
