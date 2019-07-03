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

#ifndef AWS_CRYPTOSDK_PRIVATE_FRAMEFMT_H
#define AWS_CRYPTOSDK_PRIVATE_FRAMEFMT_H

#include <aws/common/byte_buf.h>
#include <aws/common/common.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/cipher.h>

struct aws_cryptosdk_frame {
    /* The type of frame in question */
    enum aws_cryptosdk_frame_type type;
    /* The frame sequence number. For nonframed bodies, this should be 1 */
    uint32_t sequence_number;
    /* A cursor to space for the IV in the ciphertext buffer */
    struct aws_byte_buf iv;
    /* A cursor to space for the ciphertext in the ciphertext buffer */
    struct aws_byte_buf ciphertext;
    /* A cursor to space for the AEAD tag in the ciphertext buffer */
    struct aws_byte_buf authtag;
};

// MAX_FRAME_SIZE = 2^32 - 1
#define MAX_FRAME_SIZE 0xFFFFFFFF
// MAX_FRAMES = 2^32 - 1
#define MAX_FRAMES 0xFFFFFFFF
// MAX_UNFRAMED_PLAINTEXT_SIZE = 2^36 - 32
#define MAX_UNFRAMED_PLAINTEXT_SIZE 0xFFFFFFFE0ull

/**
 * Checks whether a frame struct is valid. At the moment this means
 * that it checks the validity of the byte buffers and the fact that
 * they should have NULL allocators.
 */
bool aws_cryptosdk_frame_is_valid(const struct aws_cryptosdk_frame *const frame);

/**
 * Performs frame-type-specific work prior to writing a frame; writes out all
 * fields except for the IV, ciphertext, and authtag - for those three fields,
 * this method will set the appropriate cursors in the frame structure instead;
 * it is the caller's responsibility to fill these in with the appropriate data.
 *
 * This function also checks that there is sufficient space to perform the
 * write, and if there is not, raises AWS_ERROR_SHORT_BUFFER (returning
 * AWS_OP_ERR). In this case,  the contents of the ciphertext buffer referenced
 * by the cursor are undefined, but we guarantee that space before or after the
 * cursor's range is untouched.
 *
 * On return, *ciphertext_size is always set to the amount of ciphertext
 * required to write the frame. If there was sufficient space in
 * ciphertext_buf, then *frame is initialized with cursors for the inner
 * components of the frame, *ciphertext_buf is advanced forward, and the
 * function returns AWS_OP_SUCCESS (0).
 *
 * Arguments:
 *   frame - (in/out) The frame type and sequence number are read from here;
 *           upon successful return the iv, ciphertext, and authtag cursors
 *           are pointed to the appropriate ranges within the ciphertext buffer.
 *   ciphertext_size - (out) The amount of ciphertext buffer space needed for
 *                     this frame. Always set.
 *   plaintext_size - (in) The size of the plaintext for this frame.
 *   ciphertext_buf - (in) The cursor for the ciphertext buffer. Upon success,
 *                    this cursor is advanced until it is just beyond the end
 *                    of the frame.
 *   alg_props - (in) The algorithm properties for the algorithm suite in use.
 */
int aws_cryptosdk_serialize_frame(
    struct aws_cryptosdk_frame *frame, /* in/out */
    size_t *ciphertext_size,           /* out */
    /* in */
    size_t plaintext_size,
    struct aws_byte_buf *ciphertext_buf,
    const struct aws_cryptosdk_alg_properties *alg_props);

/**
 * Attempts to parse a frame into its constituents.
 *
 * On success, the fields of the frame structure are initialized with the
 * components of the input frame. Cursors in the frame structure point directly
 * into the ciphertext buffer. The method sets *ciphertext_size and
 * *plaintext_size to the exact size of the ciphertext and plaintext frame, and
 * returns AWS_OP_SUCCESS. The input ciphertext_buf cursor is advanced to be just
 * after the frame that was parsed.
 *
 * This method can fail either because there was insufficient ciphertext on
 * input, or because the ciphertext was malformed. In the former case, it will
 * raise AWS_ERROR_SHORT_BUFFER, and in the latter case it will raise
 * AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT (either way it returns AWS_OP_ERROR).
 *
 * If a short buffer is encountered, then *ciphertext_size and *plaintext_size
 * contain a lower bound on the amount of ciphertext and plaintext in the frame.
 * This bound becomes precise when any relevant size fields are fully contained
 * in the input ciphertext fragment.
 *
 * Arguments:
 *   frame - (out) Receives the parsed frame
 *   ciphertext_size - (out) Receives the frame ciphertext size, or a lower bound thereof.
 *   plaintext_size - (out) Receives the frame plaintext size, or a lower bound thereof.
 *   ciphertext_buf - (in/out) The input ciphertext; the cursor is adjusted on success.
 *   alg_properties - (in) The algorithm properties for the algorithm suite in use.
 *   max_frame_size - (in) The maximum frame size, or zero to indicate a non-framed body.
 */
int aws_cryptosdk_deserialize_frame(
    /* out */
    struct aws_cryptosdk_frame *frame,
    size_t *ciphertext_size,
    size_t *plaintext_size,
    /* in */
    struct aws_byte_cursor *ciphertext_buf,
    const struct aws_cryptosdk_alg_properties *alg_props,
    uint64_t max_frame_size);

#endif
