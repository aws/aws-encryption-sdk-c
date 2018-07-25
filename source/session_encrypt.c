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

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <aws/common/byte_buf.h>

/* Session encrypt path routines */
void encrypt_compute_body_estimate(struct aws_cryptosdk_session *session) {
    if (session->state != ST_ENCRYPT_BODY) {
        return;
    }

    /*
     * We'll update the input/output estimates by simply doing a trial run of try_encrypt_body
     * with empty input/output buffers.
     */

    struct aws_byte_cursor empty_input = { .ptr = (uint8_t *)"", .len = 0 };
    struct aws_byte_cursor empty_output = empty_input;

    try_encrypt_body(session, &empty_output, &empty_input);
}

int try_gen_key(struct aws_cryptosdk_session *session) {
    // TODO query CMM
    // For now, the data key is all-zero
    struct data_key data_key = { { 0 } };
    uint16_t alg_id = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE;
    session->alg_props = aws_cryptosdk_alg_props(alg_id);

    if (!session->alg_props) {
        // Unknown algorithm
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    if (aws_cryptosdk_genrandom(session->header.message_id, sizeof(session->header.message_id))) {
        return AWS_OP_ERR;
    }

    int rv = aws_cryptosdk_derive_key(
        session->alg_props,
        &session->content_key,
        &data_key,
        session->header.message_id
    );

    if (rv) {
        return AWS_OP_ERR;
    }

    session->header.alg_id = alg_id;
    session->header.aad_count = 0;
    session->header.edk_count = 1;
    session->header.frame_len = session->frame_size;

    session->header.edk_tbl = aws_mem_acquire(session->alloc, sizeof(*session->header.edk_tbl));
    struct aws_cryptosdk_edk *edk = &session->header.edk_tbl[0];

    edk->provider_id = aws_byte_buf_from_c_str("null");
    edk->provider_info = aws_byte_buf_from_c_str("null");
    edk->enc_data_key = aws_byte_buf_from_c_str("");

    if (aws_byte_buf_init(session->alloc, &session->header.iv, session->alg_props->iv_len)) {
        return AWS_OP_ERR;
    }

    // TODO verify this is correct
    aws_cryptosdk_secure_zero(session->header.iv.buffer, session->alg_props->iv_len);
    session->header.iv.len = session->header.iv.capacity;

    if (aws_byte_buf_init(session->alloc, &session->header.auth_tag, session->alg_props->tag_len)) {
        return AWS_OP_ERR;
    }
    session->header.auth_tag.len = session->header.auth_tag.capacity;

    session->header_size = aws_cryptosdk_hdr_size(&session->header);

    if (!(session->header_copy = aws_mem_acquire(session->alloc, session->header_size))) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    // Debug memsets - if something goes wrong below this makes it easier to
    // see what happened. It also makes sure that the header is fully initialized,
    // again just in case some bug doesn't overwrite them properly.

    memset(session->header.iv.buffer, 0x42, session->header.iv.len);
    memset(session->header.auth_tag.buffer, 0xDE, session->header.auth_tag.len);

    size_t actual_size;
    rv = aws_cryptosdk_hdr_write(&session->header, &actual_size, session->header_copy, session->header_size);
    if (rv) return AWS_OP_ERR;
    if (actual_size != session->header_size) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    int authtag_len = session->alg_props->iv_len + session->alg_props->tag_len;
    struct aws_byte_buf to_sign = aws_byte_buf_from_array(session->header_copy, session->header_size - authtag_len);
    struct aws_byte_buf authtag = aws_byte_buf_from_array(session->header_copy + session->header_size - authtag_len, authtag_len);

    rv = aws_cryptosdk_sign_header(session->alg_props, &session->content_key, &authtag, &to_sign);
    if (rv) return AWS_OP_ERR;

    memcpy(session->header.iv.buffer, authtag.buffer, session->header.iv.len);
    memcpy(session->header.auth_tag.buffer, authtag.buffer + session->header.iv.len, session->header.auth_tag.len);

    // Re-serialize the header now that we know the auth tag
    rv = aws_cryptosdk_hdr_write(&session->header, &actual_size, session->header_copy, session->header_size);
    if (rv) return AWS_OP_ERR;
    if (actual_size != session->header_size) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    session->frame_seqno = 1;
    session_change_state(session, ST_WRITE_HEADER);

    // TODO - should we free the parsed header here?

    return AWS_OP_SUCCESS;
}

int try_write_header(
    struct aws_cryptosdk_session *session,
    struct aws_byte_cursor *output
) {
    session->output_size_estimate = session->header_size;

    // We'll only write the header if we have enough of an output buffer to
    // write the whole thing.

    // TODO - should we try to write incrementally?
    if (aws_byte_cursor_write(output, session->header_copy, session->header_size)) {
        session_change_state(session, ST_ENCRYPT_BODY);
    }

    // TODO - should we free the parsed header here?

    return AWS_OP_SUCCESS;
}

int try_encrypt_body(
    struct aws_cryptosdk_session * AWS_RESTRICT session,
    struct aws_byte_cursor * AWS_RESTRICT poutput,
    struct aws_byte_cursor * AWS_RESTRICT pinput
) {
    /* First, figure out how much plaintext we need. */
    size_t plaintext_size;
    enum aws_cryptosdk_frame_type frame_type;

    if (session->frame_size) {
        /* This is a framed message; is it the last frame? */
        if (session->precise_size_known
                && session->precise_size - session->data_so_far < session->frame_size) {
            plaintext_size = session->precise_size - session->data_so_far;
            frame_type = FRAME_TYPE_FINAL;
        } else {
            plaintext_size = session->frame_size;
            frame_type = FRAME_TYPE_FRAME;
        }
    } else {
        /* This is a non-framed message. We need the precise size before doing anything. */
        if (!session->precise_size_known) {
            session->output_size_estimate = 0;
            session->input_size_estimate = 0;
            return AWS_OP_SUCCESS;
        }

        plaintext_size = session->precise_size;
        frame_type = FRAME_TYPE_SINGLE;
    }

    /*
     * We'll use a shadow copy of the cursors; this lets us avoid modifying the
     * output if the input is too small, and vice versa.
     */
    struct aws_byte_cursor output = *poutput;
    struct aws_byte_cursor input = *pinput;

    struct aws_cryptosdk_frame frame;
    size_t ciphertext_size;

    frame.type = frame_type;
    frame.sequence_number = session->frame_seqno;

    int rv = aws_cryptosdk_serialize_frame(&frame, &ciphertext_size, plaintext_size, &output, session->alg_props);

    session->output_size_estimate = ciphertext_size;
    session->input_size_estimate = plaintext_size;

    if (rv) {
        if (aws_last_error() == AWS_ERROR_SHORT_BUFFER) {
            // The ciphertext buffer was too small. We've updated estimates;
            // just return without doing any work.
            return AWS_OP_SUCCESS;
        } else {
            // Some kind of validation failed?
            return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        }
    }

    struct aws_byte_cursor plaintext = aws_byte_cursor_advance(&input, plaintext_size);

    if (!plaintext.ptr) {
        // Not enough plaintext buffer space.
        return AWS_OP_SUCCESS;
    }

    if (aws_cryptosdk_encrypt_body(
        session->alg_props,
        &frame.ciphertext,
        &plaintext,
        session->header.message_id,
        frame.sequence_number,
        frame.iv.ptr,
        &session->content_key,
        frame.authtag.ptr,
        frame.type
    )) {
        // Something terrible happened. Clear the ciphertext buffer and error out.
        aws_cryptosdk_secure_zero(poutput->ptr, poutput->len);
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    // Success! Write back our input/output cursors now, and update our state.
    *pinput = input;
    *poutput = output;
    session->data_so_far += plaintext_size;
    session->frame_seqno++;

    if (frame.type != FRAME_TYPE_FRAME) {
        // We've written a final frame, move on to the trailer
        session_change_state(session, ST_WRITE_TRAILER);
    }

    return AWS_OP_SUCCESS;
}
