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

#include <aws/common/string.h>
#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/header.h>

enum aws_cryptosdk_aes_key_len {
    AWS_CRYPTOSDK_AES_128 = 128/8,
    AWS_CRYPTOSDK_AES_192 = 192/8,
    AWS_CRYPTOSDK_AES_256 = 256/8
};

enum aws_cryptosdk_rsa_padding_mode {
    AWS_CRYPTOSDK_RSA_PKCS1,
    AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1,
    AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1,
};

struct aws_cryptosdk_alg_properties {
    const char *md_name, *cipher_name, *alg_name;

    /**
     * Pointer to a structure containing crypto-backend-specific
     * information. This is a forward-declared structure to keep it
     * opaque to backend-independent code
     */
    const struct aws_cryptosdk_alg_impl *impl;

    size_t data_key_len, content_key_len, iv_len, tag_len, signature_len;

    enum aws_cryptosdk_alg_id alg_id;
};

const struct aws_cryptosdk_alg_properties *aws_cryptosdk_alg_props(enum aws_cryptosdk_alg_id alg_id);

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
    struct aws_cryptosdk_signctx *ctx,
    struct aws_allocator *alloc,
    struct aws_string **priv_key_buf
);

/**
 * Generates a new signature keypair, initializes a signing context, and serializes the public key.
 * If a non-signing algorithm is used, this function returns successfully, sets *ctx to NULL,
 * and zeroes pub_key_buf.
 *
 * @param alloc - the allocator to use
 * @param pctx - a pointer to a variable to receive the context pointer
 * @param props - The algorithm properties for the algorithm to use
 * @param pub_key_buf - A buffer that will receive the public key (in base64 format).
 *   This buffer will be allocated as part of this call, and does not need to be pre-initialized.
 */
int aws_cryptosdk_sig_sign_start_keygen(
    struct aws_cryptosdk_signctx **pctx,
    struct aws_allocator *alloc,
    struct aws_string **pub_key_buf,
    const struct aws_cryptosdk_alg_properties *props
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
    struct aws_cryptosdk_signctx **ctx,
    struct aws_allocator *alloc,
    struct aws_string **pub_key_buf,
    const struct aws_cryptosdk_alg_properties *props,
    const struct aws_string *priv_key
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
    struct aws_cryptosdk_signctx **pctx,
    struct aws_allocator *alloc,
    const struct aws_string *pub_key,
    const struct aws_cryptosdk_alg_properties *props
);

/**
 * Supplies some data to an ongoing sign or verify operation.
 */
int aws_cryptosdk_sig_update(
    struct aws_cryptosdk_signctx *ctx,
    const struct aws_byte_cursor buf
);

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
int aws_cryptosdk_sig_verify_finish(
    struct aws_cryptosdk_signctx *ctx,
    const struct aws_string *signature
);

/**
 * Generates the final signature based on data previously passed to aws_cryptosdk_sig_update.
 * The signature buffer will be allocated using 'alloc'.
 *
 * The context must have been created in verify mode, using aws_cryptosdk_sig_sign_start[_keygen];
 * failing to do so results in undefined behavior.
 *
 * The context is always freed, regardless of success or failure.
 */
int aws_cryptosdk_sig_sign_finish(
    struct aws_cryptosdk_signctx *ctx,
    struct aws_allocator *alloc,
    struct aws_string **signature
);

/**
 * Aborts an ongoing sign or verify operation, and destroys the signature context.
 * If ctx is null, this operation is a no-op.
 */
void aws_cryptosdk_sig_abort(
    struct aws_cryptosdk_signctx *ctx
);

#endif // AWS_CRYPTOSDK_CIPHER_H
