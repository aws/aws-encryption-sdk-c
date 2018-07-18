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
#include <aws/common/string.h>
#include <aws/common/math.h>

static int build_header(struct aws_cryptosdk_session *session, struct aws_cryptosdk_encryption_materials *materials);
static int sign_header(struct aws_cryptosdk_session *session, struct aws_cryptosdk_encryption_materials *materials);

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
    struct aws_cryptosdk_encryption_request request;
    struct aws_hash_table enc_context;
    struct aws_cryptosdk_encryption_materials *materials = NULL;
    struct data_key data_key;
    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    aws_hash_table_init(&enc_context, session->alloc, 10,
        aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy
    );

    request.alloc = session->alloc;
    request.enc_context = &enc_context;
    // TODO - the CMM should specify this
    request.requested_alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE;
    request.plaintext_size = session->precise_size_known ? session->precise_size : UINT64_MAX;

    if (aws_cryptosdk_cmm_generate_encryption_materials(
        session->cmm, &materials, &request
    )) {
        goto rethrow;
    }

    // Perform basic validation of the materials generated
    session->alg_props = aws_cryptosdk_alg_props(materials->alg);

    if (!session->alg_props) goto out;
    if (materials->unencrypted_data_key.len != session->alg_props->data_key_len) goto out;
    if (!aws_array_list_length(&materials->encrypted_data_keys)) goto out;

    // TODO - eliminate the data_key type
    memcpy(&data_key, materials->unencrypted_data_key.buffer, materials->unencrypted_data_key.len);

    // Generate message ID and derive the content key from the data key.
    if (aws_cryptosdk_genrandom(session->header.message_id, sizeof(session->header.message_id))) {
        goto out;
    }

    if (aws_cryptosdk_derive_key(
        session->alg_props,
        &session->content_key,
        &data_key,
        session->header.message_id
    )) {
        goto rethrow;
    }

    if (build_header(session, materials)) {
        goto rethrow;
    }

    if (sign_header(session, materials)) {
        goto rethrow;
    }

    result = AWS_ERROR_SUCCESS;

out:
    if (result) result = aws_raise_error(result);
    goto cleanup;
rethrow:
    result = AWS_OP_ERR;
cleanup:
    if (materials) {
        aws_cryptosdk_secure_zero_buf(&materials->unencrypted_data_key);
        aws_cryptosdk_encryption_materials_destroy(materials);
    }

    aws_cryptosdk_secure_zero(&data_key, sizeof(data_key));
    aws_hash_table_clean_up(&enc_context);

    return result;
}

static int build_header(struct aws_cryptosdk_session *session, struct aws_cryptosdk_encryption_materials *materials) {
    session->header.alg_id = session->alg_props->alg_id;
    // TODO: aad
    session->header.aad_count = 0;
    session->header.edk_count = aws_array_list_length(&materials->encrypted_data_keys);
    session->header.frame_len = session->frame_size;

    size_t edk_tbl_size, aad_tbl_size;
    if (!aws_mul_size_checked(session->header.aad_count, sizeof(*session->header.aad_tbl), &aad_tbl_size)
        || !aws_mul_size_checked(session->header.edk_count, sizeof(*session->header.edk_tbl), &edk_tbl_size)) {
        // Unlikely to happen on modern platforms (the count fields are uint16_ts) but just in case...
        return aws_raise_error(AWS_ERROR_OOM);
    }

    session->header.edk_tbl = aws_mem_acquire(session->alloc, edk_tbl_size);
    if (!session->header.edk_tbl) return AWS_OP_ERR; // already raised OOM
    session->header.aad_tbl = aws_mem_acquire(session->alloc, aad_tbl_size);
    if (!session->header.aad_tbl) return AWS_OP_ERR;

    // Transfer EDKs. We need them to survide the destruction of the materials, so we'll clear the list in materials
    // when we're done.
    for (uint32_t i = 0; i < session->header.edk_count; i++) {
        if (aws_array_list_get_at(&materials->encrypted_data_keys, &session->header.edk_tbl[i], i)) {
            // impossible condition; but just in case, we check

            // Avoid double-free - materials->encrypted_data_keys still references the inner buffers
            aws_cryptosdk_secure_zero(session->header.edk_tbl, edk_tbl_size);
            return AWS_OP_ERR;
        }
    }

    // TODO verify that the zero IV is correct for the header IV
    aws_byte_buf_init(session->alloc, &session->header.iv, session->alg_props->iv_len);
    aws_cryptosdk_secure_zero(session->header.iv.buffer, session->alg_props->iv_len);
    session->header.iv.len = session->header.iv.capacity;

    if (aws_byte_buf_init(session->alloc, &session->header.auth_tag, session->alg_props->tag_len)) {
        return AWS_OP_ERR;
    }
    session->header.auth_tag.len = session->header.auth_tag.capacity;

    return AWS_OP_SUCCESS;
}

static int sign_header(struct aws_cryptosdk_session *session, struct aws_cryptosdk_encryption_materials *materials) {
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
    int rv = aws_cryptosdk_hdr_write(&session->header, &actual_size, session->header_copy, session->header_size);
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
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
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
