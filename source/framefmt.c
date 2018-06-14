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

#include <aws/cryptosdk/private/framefmt.h>
#include <aws/cryptosdk/error.h>
#include <aws/common/error.h>

#define LAST_FRAME_MARK 0xFFFFFFFFu

struct aws_cryptosdk_framestate {
    uint64_t max_frame_size;
    uint64_t plaintext_size;
    uint64_t ciphertext_size;
    const struct aws_cryptosdk_alg_properties * AWS_RESTRICT alg_props;
    struct aws_byte_cursor cursor;

    /*
     * The writing field indicates if we intend to write data; in particular,
     * this means that fields like sequence_number and plaintext_size are inputs
     * to the serde functions.
     */
    bool writing;

    /*
     * True if we don't have enough room in the ciphertext stream to read/write
     * this frame. Note that ciphertext_size is updated with a lower bound on the
     * size needed even if we can't read/write the whole frame.
     *
     * Note that the serde functions don't /fail/ on short buffer. They just don't
     * fully serialize or deserialize. The top level aws_cryptosdk_deserialize_frame and
     * aws_cryptosdk_serialize_frame functions deal with translating to raised errors.
     */
    bool too_small;
};

/*
 * This macro helps read or write a fixed-sized integer as part of a serde function.
 * Depending on the writing flag, we either read or write a field by delegating to
 * aws_byte_cursor_[read/write]_[suffix].
 *
 * Note that fieldptr does not need to be of type 'type'. This helps in cases where
 * the underlying field we want to write (in memory) is of one type but the serialized
 * type depends on the frame type (e.g. the body size field is a different size for
 * non-framed bodies and final frames). We use a temporary variable to perform integer
 * up/downconversion in this case.
 *
 * It's also worth noting that we do not bail out of the underlying function. This is
 * because we want to get the best estimate of the ciphertext size we can; if we have
 * insufficient data, we continue counting up fields beyond the end of the buffer (but
 * don't actually read or write beyond the end of the buffer, thanks to the byte cursor
 * macros).
 *
 * Arguments:
 *   type - the type of the field to write/read
 *   suffix - the suffix of aws_byte_cursor_[read/write]_* to use
 *   state - a pointer to a framestate structure. This pointer may be evaluated multiple
 *           times.
 *   fieldptr - a pointer to an integer field that will contain/receive the value to write/read.
 *              This does not need to be of type 'type'.
 */
#define field_helper(type, suffix, state, fieldptr) do { \
    (state)->ciphertext_size += sizeof(type); \
    if ((state)->writing) { \
        type tmp_field = *(fieldptr); \
        (state)->too_small = (state)->too_small || !aws_byte_cursor_write_##suffix(&(state)->cursor, tmp_field); \
    } else { \
        type tmp_field = 0; \
        (state)->too_small = (state)->too_small || !aws_byte_cursor_read_##suffix(&(state)->cursor, &tmp_field); \
        *(fieldptr) = tmp_field; \
    } \
} while (0)


/*
 * Predefined macros for reading/writing big-endian fields of 32 or 64 bits.
 */
#define field_be32(state, fieldptr) field_helper(uint32_t, be32, state, fieldptr)
#define field_be64(state, fieldptr) field_helper(uint64_t, be64, state, fieldptr)

/*
 * This macro helps read or write a variable-sized field. We will attempt to set
 * the cursor at 'cursorptr' to refer to a block of 'size' bytes within the ciphertext
 * buffer.
 */
#define field_sized(state, cursorptr, size) do { \
    (state)->ciphertext_size += (size); \
    *(cursorptr) = aws_byte_cursor_advance(&(state)->cursor, (size)); \
    (state)->too_small = (state)->too_small || !(cursorptr)->ptr; \
} while (0)

static int serde_last_frame(
    struct aws_cryptosdk_framestate * AWS_RESTRICT state,
    struct aws_cryptosdk_frame * AWS_RESTRICT frame
);

/*
 * The following serde_ functions both serialize and deserialize various kinds of frames.
 * In general, they return AWS_ERROR_SUCCESS if either (de)serialization was successful or
 * the ciphertext buffer was too small; if they encounter some other error, they return that
 * error code (_without_ raising it).
 */
static inline int serde_framed(
    struct aws_cryptosdk_framestate * AWS_RESTRICT state,
    struct aws_cryptosdk_frame * AWS_RESTRICT frame
) {
    uint32_t seqno_mark = frame->sequence_number;

    if (state->writing) {
        if (frame->type == FRAME_TYPE_FINAL) {
            // For the final frame, we start by writing a sentinel (0xFFFFFFFF) which indicates
            // that the subsequent frame is a final frame.
            seqno_mark = LAST_FRAME_MARK;
        } else if (seqno_mark == LAST_FRAME_MARK) {
            // Make sure we don't try to write an intermediate frame of sequence number 0xFFFFFFFF
            // as this would be misinterpreted as a final frame.
            return AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED;
        }
    }

    // Note that if we don't have four bytes in the buffer, we'll assume seqno_mark
    // to be zero for the purposes of subsequent logic in the serde function.
    field_be32(state, &seqno_mark);

    if (seqno_mark == LAST_FRAME_MARK) {
        return serde_last_frame(state, frame);
    }

    // When writing, this is unchanged from the original frame->sequence_number
    // since we know we're not in a final frame.
    frame->sequence_number = seqno_mark;

    // When reading, we need to always initialize the plaintext_size field.
    // On a write this is a no-op as this is already initialized to the frame size.
    state->plaintext_size = state->max_frame_size;

    field_sized(state, &frame->iv, state->alg_props->iv_len);
    field_sized(state, &frame->ciphertext, state->plaintext_size);
    field_sized(state, &frame->authtag, state->alg_props->tag_len);

    frame->type = FRAME_TYPE_FRAME;

    return AWS_ERROR_SUCCESS;
}

static inline int serde_last_frame(
    struct aws_cryptosdk_framestate * AWS_RESTRICT state,
    struct aws_cryptosdk_frame * AWS_RESTRICT frame
) {
    // The final frame mark has already been read when we enter this function
    // from serde_framed.

    field_be32(state, &frame->sequence_number);
    field_sized(state, &frame->iv, state->alg_props->iv_len);
    field_be32(state, &state->plaintext_size);

    // The final frame is not allowed to be larger than intermediate frames.
    // It _can_ however be zero bytes in size, or equal to intermediate frame
    // sizes.
    if (state->plaintext_size > state->max_frame_size) {
        return AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT;
    }

    field_sized(state, &frame->ciphertext, state->plaintext_size);
    field_sized(state, &frame->authtag, state->alg_props->tag_len);

    frame->type = FRAME_TYPE_FINAL;

    return AWS_ERROR_SUCCESS;
}

static inline int serde_nonframed(
    struct aws_cryptosdk_framestate * AWS_RESTRICT state,
    struct aws_cryptosdk_frame * AWS_RESTRICT frame
) {
    field_sized(state, &frame->iv, state->alg_props->iv_len);
    field_be64(state, &state->plaintext_size);
    field_sized(state, &frame->ciphertext, state->plaintext_size);
    field_sized(state, &frame->authtag, state->alg_props->tag_len);

    // Non-framed bodies don't actually have sequence numbers, but we treat
    // them as having a seqno of 1 for consistency.
    frame->sequence_number = 1;
    frame->type = FRAME_TYPE_SINGLE;

    return AWS_ERROR_SUCCESS;
}

/**
 * Performs frame-type-specific work prior to writing a frame; writes out all
 * fields except for the IV, ciphertext, and authtag, and returns their
 * locations.
 *
 * This function also checks that there is sufficient space to perform the
 * write, and if there is not, returns false.
 *
 * On return, *ciphertext_size is always set to the amount of ciphertext
 * required to write the frame. If there was sufficient space in
 * ciphertext_buf, then *frame is initialized with cursors for the inner
 * components of the frame, *ciphertext_buf is advanced forward, and the
 * function returns true.
 */
int aws_cryptosdk_serialize_frame(
    /* out */
    struct aws_cryptosdk_frame *frame,
    size_t *ciphertext_size,
    /* in */
    size_t plaintext_size,
    struct aws_byte_cursor *ciphertext_buf,
    const struct aws_cryptosdk_alg_properties *alg_props
) {
    struct aws_cryptosdk_framestate state;

    // We assume that the max frame size is equal to the plaintext size. This
    // lets us avoid having to pass in a redundant argument, avoids needing to
    // take a branch in serde_framed, and does not impact the serialized
    // output.
    state.max_frame_size = plaintext_size;
    state.plaintext_size = plaintext_size;
    // Currently all supported algorithms have plaintext = ciphertext size
    state.ciphertext_size = plaintext_size;

    state.alg_props = alg_props;
    state.cursor = *ciphertext_buf;

    state.writing = true;
    state.too_small = false;

    int result;
    if (frame->type == FRAME_TYPE_SINGLE) {
        result = serde_nonframed(&state, frame);
    } else {
        result = serde_framed(&state, frame);
    }

    if (result == AWS_ERROR_SUCCESS && state.too_small) {
        result = AWS_ERROR_SHORT_BUFFER;
    }

    *ciphertext_size = state.ciphertext_size;

    if (result != AWS_ERROR_SUCCESS) {
        // Clear any garbage we wrote
        aws_cryptosdk_secure_zero(ciphertext_buf->ptr, ciphertext_buf->len);
        return aws_raise_error(result);
    } else {
        *ciphertext_buf = state.cursor;
        return AWS_OP_SUCCESS;
    }
}

/**
 * Attempts to parse a frame into its constituents.
 * 
 * If there was enough ciphertext to parse the frame, then *frame,
 * *ciphertext_size, and *plaintext_size are initialized with the components
 * and size of the frame accordingly, and the function returns true.
 *
 * If there was not enough ciphertext to parse the frame, then *frame is
 * zeroed, and *ciphertext_size and *plaintext_size contain a lower bound on
 * the size of the frame. This bound becomes precise if enough of the frame has
 * been provided to determine the frame size.
 */
int aws_cryptosdk_deserialize_frame(
    /* out */
    struct aws_cryptosdk_frame *frame,
    size_t *ciphertext_size,
    size_t *plaintext_size,
    /* in */
    struct aws_byte_cursor *ciphertext_buf,
    const struct aws_cryptosdk_alg_properties *alg_props,
    uint64_t max_frame_size
) {
    struct aws_cryptosdk_framestate state;
    state.max_frame_size = max_frame_size;
    state.plaintext_size = 0;
    state.ciphertext_size = 0;

    state.alg_props = alg_props;
    state.cursor = *ciphertext_buf;

    state.writing = false;
    state.too_small = false;

    aws_cryptosdk_secure_zero(frame, sizeof(*frame));

    int result;

    if (max_frame_size) {
        result = serde_framed(&state, frame);
    } else {
        result = serde_nonframed(&state, frame);
    }

    if (result == AWS_ERROR_SUCCESS && state.too_small) {
        result = AWS_ERROR_SHORT_BUFFER;
    }

    *plaintext_size = state.plaintext_size;
    *ciphertext_size = state.ciphertext_size;

    if (result != AWS_ERROR_SUCCESS) {
        // Don't leak a partially-initialized structure
        aws_cryptosdk_secure_zero(frame, sizeof(*frame));
        return aws_raise_error(result);
    } else {
        *ciphertext_buf = state.cursor;
        return AWS_OP_SUCCESS;
    }
}


