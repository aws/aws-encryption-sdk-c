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

#ifndef AWS_CRYPTOSDK_CIPHER_H
#define AWS_CRYPTOSDK_CIPHER_H

#include <aws/common/byte_buf.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/exports.h>
#include <aws/cryptosdk/header.h>

/**
 * @addtogroup hazmat Low-level cryptographic APIs
 * These low-level cryptographic APIs should normally only be used by developers of keyrings or CMMs.
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup raw_keyring */
enum aws_cryptosdk_aes_key_len {
    AWS_CRYPTOSDK_AES128 = 128 / 8,
    AWS_CRYPTOSDK_AES192 = 192 / 8,
    AWS_CRYPTOSDK_AES256 = 256 / 8
};

/** @ingroup raw_keyring */
enum aws_cryptosdk_rsa_padding_mode {
    AWS_CRYPTOSDK_RSA_PKCS1,
    AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1,
    AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1,
};

/* This is large enough to hold an encoded public key for all currently supported curves */
#define MAX_PUBKEY_SIZE 64
#define MAX_PUBKEY_SIZE_B64 (((MAX_PUBKEY_SIZE + 2) * 4) / 3)

/**
 * This structure contains information about a particular algorithm suite used
 * within the encryption SDK.  In most cases, end-users don't need to
 * manipulate this structure, but it can occasionally be needed for more
 * advanced use cases, such as writing keyrings.
 */
struct aws_cryptosdk_alg_properties {
    /** The name of the digest algorithm used for the KDF, or NULL if no KDF is used. */
    const char *md_name;
    /** The name of the symmetric cipher in use. */
    const char *cipher_name;
    /** The name of the overall algorithm suite in use (for debugging purposes) */
    const char *alg_name;

    /**
     * Pointer to a structure containing crypto-backend-specific
     * information. This is a forward-declared structure to keep it
     * opaque to backend-independent code
     */
    const struct aws_cryptosdk_alg_impl *impl;

    /** The length of the data key (that is, the key returned by the keyrings/CMMs) */
    size_t data_key_len;
    /**
     * The length of the key used to actually encrypt/decrypt data. This may differ
     * if a KDF is in use.
     */
    size_t content_key_len;
    /** The IV length for this algorithm suite */
    size_t iv_len;
    /**
     * The AEAD tag length for this algorithm suite. Note that, currently, we only
     * support stream-like ciphers that do not require padding, so the ciphertext
     * size is equal to the plaintext size plus tag (and IV, if you pre/append IV).
     */
    size_t tag_len;
    /**
     * The length of the trailing signature. Zero if there is no trailing signature
     * for this algorithm suite.
     */
    size_t signature_len;

    /**
     * The algorithm ID for this algorithm suite
     */
    enum aws_cryptosdk_alg_id alg_id;
};

/**
 * Looks up and returns the algorithm properties for a particular algorithm ID.
 *
 * @returns the algorithm properties, or NULL if alg_id is unknown
 */
AWS_CRYPTOSDK_API
const struct aws_cryptosdk_alg_properties *aws_cryptosdk_alg_props(enum aws_cryptosdk_alg_id alg_id);

/**
 * An opaque structure representing an ongoing sign or verify operation
 */
struct aws_cryptosdk_sig_ctx;

/**
 * Performs basic validity checks for the signing context (e.g. that member pointers are not NULL).
 */
AWS_CRYPTOSDK_API
bool aws_cryptosdk_sig_ctx_is_valid(const struct aws_cryptosdk_sig_ctx *sig_ctx);

/**
 * Obtains the private key from a signing context, and serializes it to a byte buffer.
 * The serialization format is not currently guaranteed to remain unchanged.
 *
 * This method is intended to be used with caching mechanisms to clone the signing context.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_get_privkey(
    const struct aws_cryptosdk_sig_ctx *ctx, struct aws_allocator *alloc, struct aws_string **priv_key_buf);

/**
 * Obtains the public key from a signing context, which may be in either sign or verify
 * mode, and serializes it to a byte buffer.
 *
 * This method is intended to be used with caching mechanisms to clone a verification context.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_get_pubkey(
    const struct aws_cryptosdk_sig_ctx *ctx, struct aws_allocator *alloc, struct aws_string **pub_key_buf);

/**
 * Generates a new signature keypair, initializes a signing context, and serializes the public key.
 * If a non-signing algorithm is used, this function returns successfully, sets *ctx to NULL,
 * and zeroes pub_key_buf.
 *
 * @param ctx - a pointer to a variable to receive the context pointer
 * @param alloc - the allocator to use
 * @param pub_key_buf - A buffer that will receive the public key (in base64 format).
 *   This buffer will be allocated as part of this call, and does not need to be pre-initialized.
 * @param props - The algorithm properties for the algorithm to use
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_sign_start_keygen(
    struct aws_cryptosdk_sig_ctx **ctx,
    struct aws_allocator *alloc,
    struct aws_string **pub_key_buf,
    const struct aws_cryptosdk_alg_properties *props);

/**
 * Initializes a new signature context based on a private key serialized using
 * aws_cryptosdk_sig_get_privkey.
 *
 * @param ctx a pointer to a variable to receive the signing context
 * @param alloc the allocator to use
 * @param pub_key_buf a pointer to a buffer that will receive the base-64 public key,
 *     or NULL if not required
 * @param props algorithm properties for the algorithm suite in use
 * @param priv_key the previously serialized private key
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_sign_start(
    struct aws_cryptosdk_sig_ctx **ctx,
    struct aws_allocator *alloc,
    struct aws_string **pub_key_buf,
    const struct aws_cryptosdk_alg_properties *props,
    const struct aws_string *priv_key);

/**
 * Prepares to validate a signature.
 * If a non-signing algorithm is used, this function returns successfully, and sets *ctx to NULL.
 *
 * @param ctx a pointer to a variable to receive the context pointer
 * @param alloc the allocator to use
 * @param pub_key A buffer containing the (base64) public key
 * @param props The algorithm properties for the algorithm to use
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_verify_start(
    struct aws_cryptosdk_sig_ctx **ctx,
    struct aws_allocator *alloc,
    const struct aws_string *pub_key,
    const struct aws_cryptosdk_alg_properties *props);

/**
 * Supplies some data to an ongoing sign or verify operation.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_update(struct aws_cryptosdk_sig_ctx *ctx, const struct aws_byte_cursor buf);

/**
 * Verifies a signature against the data previously passed to aws_cryptosdk_sig_update.
 * If successful, this function returns AWS_OP_SUCCESS; if the signature was invalid,
 * raises AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT and returns AWS_OP_ERR.
 *
 * The context must have been created in verify mode, using aws_cryptosdk_sig_verify_start;
 * failing to do so results in undefined behavior.
 *
 * The context is always freed, regardless of success or failure.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_verify_finish(struct aws_cryptosdk_sig_ctx *ctx, const struct aws_string *signature);

/**
 * Generates the final signature based on data previously passed to aws_cryptosdk_sig_update.
 * The signature buffer will be allocated using 'alloc'.
 *
 * The context must have been created in verify mode, using aws_cryptosdk_sig_sign_start[_keygen];
 * failing to do so results in undefined behavior.
 *
 * The context is always freed, regardless of success or failure.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_sig_sign_finish(
    struct aws_cryptosdk_sig_ctx *ctx, struct aws_allocator *alloc, struct aws_string **signature);

/**
 * Aborts an ongoing sign or verify operation, and destroys the signature context.
 * If ctx is null, this operation is a no-op.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_sig_abort(struct aws_cryptosdk_sig_ctx *ctx);

#ifdef __cplusplus
}
#endif

/*! @} */  // doxygen group hazmat

#endif  // AWS_CRYPTOSDK_CIPHER_H
