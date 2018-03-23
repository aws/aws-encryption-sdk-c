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

#ifndef AWS_CRYPTOSDK_P_CIPHER_H
#define AWS_CRYPTOSDK_P_CIPHER_H

#include <aws/cryptosdk/header.h>
#include <aws/common/byte_buf.h>

/**
 * Internal cryptographic helpers.
 * This header is not installed and is not a stable API.
 */

#define MAX_KEY_SIZE 32

struct data_key {
    uint8_t keybuf[MAX_KEY_SIZE];
};

struct content_key {
    uint8_t keybuf[MAX_KEY_SIZE];
};

/**
 * Derive the decryption key from the data key.
 * Depending on the algorithm ID, this either does a HKDF,
 * or a no-op copy of the key.
 */
int aws_cryptosdk_derive_key(
    struct content_key *content_key,
    const struct data_key *data_key,
    enum aws_cryptosdk_alg_id alg_id,
    const uint8_t *message_id
);

/**
 * Verifies the header authentication tag.
 * Returns AWS_OP_SUCCESS if the tag is valid, raises AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT
 * if invalid.
 */
int aws_cryptosdk_verify_header(
    enum aws_cryptosdk_alg_id alg_id,
    const struct content_key *content_key,
    const struct aws_byte_buf *authtag,
    const struct aws_byte_buf *header
);

#define FRAME_TYPE_SINGLE 0
#define FRAME_TYPE_FRAME 1
#define FRAME_TYPE_FINAL 2

// TODO: Initialize the cipher once and reuse it
/**
 * Decrypts either the body of the message (for non-framed messages) or a single frame of the message.
 * Returns AWS_OP_SUCCESS if successful.
 */
int aws_cryptosdk_decrypt_body(
    struct aws_byte_buf *out,
    const struct aws_byte_buf *in,
    enum aws_cryptosdk_alg_id alg_id,
    const uint8_t *message_id,
    uint32_t seqno,
    const uint8_t *iv,
    const struct content_key *key,
    const uint8_t *tag,
    int body_frame_type
);

int aws_cryptosdk_genrandom(
    uint8_t *buf,
    size_t len
);

// TODO: Footer

static inline void aws_cryptosdk_secure_zero(void *buf, size_t len) {
    memset(buf, 0, len);
    // Perform a compiler memory barrier to ensure that the memset is not eliminated
    __asm__ __volatile__("" :: "r" (buf) : "memory");

    // TODO: MSVC/win32 support using SecureZero
}

#endif // AWS_CRYPTOSDK_P_CIPHER_H
