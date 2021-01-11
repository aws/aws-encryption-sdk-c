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

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include <aws/common/byte_buf.h>
#include <aws/common/math.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/list_utils.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>

#ifdef UNIT_TEST_ONLY_ALLOW_ENCRYPT_WITH_COMMITMENT
bool unit_test_only_allow_encrypt_with_commitment = false;
#else
#    define unit_test_only_allow_encrypt_with_commitment false
#endif

static int build_header(struct aws_cryptosdk_session *session, struct aws_cryptosdk_enc_materials *materials);
static int sign_header(struct aws_cryptosdk_session *session);

/* Session encrypt path routines */
void aws_cryptosdk_priv_encrypt_compute_body_estimate(struct aws_cryptosdk_session *session) {
    if (session->state != ST_ENCRYPT_BODY) {
        return;
    }

    /*
     * We'll update the input/output estimates by simply doing a trial run of aws_cryptosdk_priv_try_encrypt_body
     * with empty input/output buffers.
     */

    struct aws_byte_cursor empty_input = { .ptr = (uint8_t *)"", .len = 0 };
    struct aws_byte_buf empty_output   = { .buffer = NULL, .len = 0, .capacity = 0 };

    aws_cryptosdk_priv_try_encrypt_body(session, &empty_output, &empty_input);
}

int aws_cryptosdk_priv_try_gen_key(struct aws_cryptosdk_session *session) {
    struct aws_cryptosdk_enc_request request;
    struct aws_cryptosdk_enc_materials *materials = NULL;
    struct data_key data_key;
    int result = AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN;

    request.alloc   = session->alloc;
    request.enc_ctx = &session->header.enc_ctx;
    // The default CMM will fill this in.
    request.requested_alg  = 0;
    request.plaintext_size = session->precise_size_known ? session->precise_size : session->size_bound;

    if (aws_cryptosdk_cmm_generate_enc_materials(session->cmm, &materials, &request)) {
        goto rethrow;
    }

    // Perform basic validation of the materials generated
    session->alg_props = aws_cryptosdk_alg_props(materials->alg);

    if (!session->alg_props) goto out;
    if (materials->unencrypted_data_key.len != session->alg_props->data_key_len) goto out;
    if (!aws_array_list_length(&materials->encrypted_data_keys)) goto out;
    // We should have a signature context iff this is a signed alg suite
    if (!!session->alg_props->signature_len != !!materials->signctx) goto out;
    if (!aws_cryptosdk_priv_algorithm_allowed_for_encrypt(materials->alg, session->commitment_policy) &&
        !unit_test_only_allow_encrypt_with_commitment) {
        result = AWS_CRYPTOSDK_ERR_COMMITMENT_POLICY_VIOLATION;
        goto out;
    }

    // Move ownership of the signature context before we go any further.
    session->signctx   = materials->signctx;
    materials->signctx = NULL;

    // TODO - eliminate the data_key type
    memcpy(&data_key, materials->unencrypted_data_key.buffer, materials->unencrypted_data_key.len);

    aws_cryptosdk_transfer_list(&session->keyring_trace, &materials->keyring_trace);
    session->cmm_success = true;

    // Generate message ID and derive the content key from the data key.
    size_t message_id_len = aws_cryptosdk_private_algorithm_message_id_len(session->alg_props);
    aws_byte_buf_init(&session->header.message_id, session->alloc, message_id_len);
    if (aws_cryptosdk_genrandom(session->header.message_id.buffer, message_id_len)) {
        goto out;
    }
    session->header.message_id.len = message_id_len;

    if (aws_cryptosdk_commitment_policy_should_commit_on_encrypt(session->commitment_policy) ||
        unit_test_only_allow_encrypt_with_commitment) {
        assert(session->alg_props->commitment_len <= sizeof(session->key_commitment_arr));
        session->header.alg_suite_data =
            aws_byte_buf_from_array(session->key_commitment_arr, session->alg_props->commitment_len);
    }

    if (aws_cryptosdk_private_derive_key(
            session->alg_props,
            &session->content_key,
            &data_key,
            &session->header.alg_suite_data,
            &session->header.message_id)) {
        goto rethrow;
    }

    if (build_header(session, materials)) {
        goto rethrow;
    }

    if (sign_header(session)) {
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
        aws_byte_buf_secure_zero(&materials->unencrypted_data_key);
        aws_cryptosdk_enc_materials_destroy(materials);
    }

    aws_secure_zero(&data_key, sizeof(data_key));

    return result;
}

static int build_header(struct aws_cryptosdk_session *session, struct aws_cryptosdk_enc_materials *materials) {
    session->header.alg_id = session->alg_props->alg_id;
    if (session->frame_size > UINT32_MAX) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }
    session->header.frame_len = (uint32_t)session->frame_size;

    // Swap the materials' EDK list for the header's. Note that these both use the session allocator
    // (aws_array_list_swap_contents requires that both lists use the same allocator).
    // When we clean up the materials structure we'll destroy the old EDK list.

    aws_array_list_swap_contents(&session->header.edk_list, &materials->encrypted_data_keys);

    // The header should have been cleared earlier, so the materials structure should have
    // zero EDKs (otherwise we'd need to destroy the old EDKs as well).
    assert(aws_array_list_length(&materials->encrypted_data_keys) == 0);

    if (aws_byte_buf_init(&session->header.iv, session->alloc, session->alg_props->iv_len)) {
        return AWS_OP_ERR;
    }
    aws_secure_zero(session->header.iv.buffer, session->alg_props->iv_len);
    session->header.iv.len = session->header.iv.capacity;

    if (aws_byte_buf_init(&session->header.auth_tag, session->alloc, session->alg_props->tag_len)) {
        return AWS_OP_ERR;
    }
    session->header.auth_tag.len = session->header.auth_tag.capacity;

    return AWS_OP_SUCCESS;
}

static int sign_header(struct aws_cryptosdk_session *session) {
    AWS_PRECONDITION(aws_cryptosdk_session_is_valid(session));
    AWS_PRECONDITION(session->alg_props->impl->cipher_ctor != NULL);
    AWS_PRECONDITION(session->header.iv.len <= session->alg_props->iv_len);
    AWS_PRECONDITION(session->header.auth_tag.len <= session->alg_props->tag_len);
    AWS_PRECONDITION(session->state == ST_GEN_KEY);
    AWS_PRECONDITION(session->mode == AWS_CRYPTOSDK_ENCRYPT);
    session->header_size = aws_cryptosdk_hdr_size(&session->header);

    if (session->header_size == 0) {
        // EDK field lengths resulted in size_t overflow
        return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    if (!(session->header_copy = aws_mem_acquire(session->alloc, session->header_size))) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    // Debug memsets - if something goes wrong below this makes it easier to
    // see what happened. It also makes sure that the header is fully initialized,
    // again just in case some bug doesn't overwrite them properly.

    if (session->header.iv.len != 0) {
        assert(session->header.iv.buffer);
        memset(session->header.iv.buffer, 0x42, session->header.iv.len);
    }
    if (session->header.auth_tag.len != 0) {
        assert(session->header.auth_tag.buffer);
        memset(session->header.auth_tag.buffer, 0xDE, session->header.auth_tag.len);
    }

    size_t actual_size;

    int rv = aws_cryptosdk_hdr_write(&session->header, &actual_size, session->header_copy, session->header_size);

    if (rv) return AWS_OP_ERR;
    if (actual_size != session->header_size) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    size_t authtag_len = aws_cryptosdk_private_authtag_len(session->alg_props);

    struct aws_byte_buf to_sign = aws_byte_buf_from_array(session->header_copy, session->header_size - authtag_len);
    struct aws_byte_buf authtag =
        aws_byte_buf_from_array(session->header_copy + session->header_size - authtag_len, authtag_len);

    rv = aws_cryptosdk_sign_header(session->alg_props, &session->content_key, &authtag, &to_sign);
    if (rv) return AWS_OP_ERR;

    if (session->alg_props->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_1_0) {
        if (session->header.iv.len != 0) {
            assert(session->header.iv.buffer);
            memcpy(session->header.iv.buffer, authtag.buffer, session->header.iv.len);
        }
        if (session->header.auth_tag.len != 0) {
            assert(session->header.auth_tag.buffer);
            memcpy(
                session->header.auth_tag.buffer, authtag.buffer + session->header.iv.len, session->header.auth_tag.len);
        }
    } else {
        if (session->header.auth_tag.len != 0) {
            assert(session->header.auth_tag.buffer);
            memcpy(session->header.auth_tag.buffer, authtag.buffer, session->header.auth_tag.len);
        }
    }

    // Re-serialize the header now that we know the auth tag
    rv = aws_cryptosdk_hdr_write(&session->header, &actual_size, session->header_copy, session->header_size);
    if (rv) return AWS_OP_ERR;
    if (actual_size != session->header_size) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (session->signctx &&
        aws_cryptosdk_sig_update(
            session->signctx, aws_byte_cursor_from_array(session->header_copy, session->header_size))) {
        return AWS_OP_ERR;
    }

    session->frame_seqno = 1;
    aws_cryptosdk_priv_session_change_state(session, ST_WRITE_HEADER);

    // TODO - should we free the parsed header here?

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_priv_try_write_header(struct aws_cryptosdk_session *session, struct aws_byte_buf *output) {
    session->output_size_estimate = session->header_size;

    // We'll only write the header if we have enough of an output buffer to
    // write the whole thing.

    // TODO - should we try to write incrementally?
    if (aws_byte_buf_write(output, session->header_copy, session->header_size)) {
        aws_cryptosdk_priv_session_change_state(session, ST_ENCRYPT_BODY);
    }

    // TODO - should we free the parsed header here?

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_priv_try_encrypt_body(
    struct aws_cryptosdk_session *AWS_RESTRICT session,
    struct aws_byte_buf *AWS_RESTRICT poutput,
    struct aws_byte_cursor *AWS_RESTRICT pinput) {
    /* First, figure out how much plaintext we need. */
    size_t plaintext_size;
    enum aws_cryptosdk_frame_type frame_type;

    if (session->frame_size) {
        /* This is a framed message; is it the last frame? */
        if (session->precise_size_known && session->precise_size - session->data_so_far < session->frame_size) {
            plaintext_size = (size_t)(session->precise_size - session->data_so_far);
            frame_type     = FRAME_TYPE_FINAL;
        } else {
            plaintext_size = (size_t)session->frame_size;
            frame_type     = FRAME_TYPE_FRAME;
        }
    } else {
        /* This is a non-framed message. We need the precise size before doing anything. */
        if (!session->precise_size_known) {
            session->output_size_estimate = 0;
            session->input_size_estimate  = 0;
            return AWS_OP_SUCCESS;
        }

        plaintext_size = (size_t)session->precise_size;
        frame_type     = FRAME_TYPE_SINGLE;
    }

    /*
     * We'll use a shadow copy of the cursors; this lets us avoid modifying the
     * output if the input is too small, and vice versa.
     */
    struct aws_byte_buf output   = *poutput;
    struct aws_byte_cursor input = *pinput;

    struct aws_cryptosdk_frame frame;
    size_t ciphertext_size;

    frame.type = frame_type;
    if (session->frame_seqno > UINT32_MAX) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }
    frame.sequence_number = session->frame_seqno;

    int rv = aws_cryptosdk_serialize_frame(&frame, &ciphertext_size, plaintext_size, &output, session->alg_props);

    session->output_size_estimate = ciphertext_size;
    session->input_size_estimate  = plaintext_size;

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
            &session->header.message_id,
            frame.sequence_number,
            frame.iv.buffer,
            &session->content_key,
            frame.authtag.buffer,
            frame.type)) {
        // Something terrible happened. Clear the ciphertext buffer and error out.
        aws_byte_buf_secure_zero(poutput);
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (session->signctx) {
        // Note that the 'output' buffer contains only our ciphertext; we need to keep track of the frame
        // headers as well

        uint8_t *original_start = poutput->buffer + poutput->len;
        uint8_t *current_end    = output.buffer + output.len;

        struct aws_byte_cursor to_sign = aws_byte_cursor_from_array(original_start, current_end - original_start);

        if (aws_cryptosdk_sig_update(session->signctx, to_sign)) {
            // Something terrible happened. Clear the ciphertext buffer and error out.
            aws_secure_zero(original_start, current_end - original_start);
            return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
        }
    }

    // Success! Write back our input/output cursors now, and update our state.
    *pinput  = input;
    *poutput = output;
    session->data_so_far += plaintext_size;
    session->frame_seqno++;

    if (frame.type != FRAME_TYPE_FRAME) {
        // We've written a final frame, move on to the trailer
        aws_cryptosdk_priv_session_change_state(session, ST_WRITE_TRAILER);
    }

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_priv_write_trailer(
    struct aws_cryptosdk_session *AWS_RESTRICT session, struct aws_byte_buf *AWS_RESTRICT poutput) {
    /* We definitely do not need any more input at this point.
     * We might need more output space, and if so we will update the
     * output estimate below. For now we set it to zero so that when
     * session is done both estimates will be zero.
     */
    session->input_size_estimate  = 0;
    session->output_size_estimate = 0;

    if (session->alg_props->signature_len == 0) {
        aws_cryptosdk_priv_session_change_state(session, ST_DONE);
        return AWS_OP_SUCCESS;
    }

    // The trailer frame is a 16-bit length followed by the signature.
    // Since we generate the signature with a deterministic size, we know how much space we need
    // ahead of time.
    size_t size_needed = 2 + session->alg_props->signature_len;
    if (poutput->capacity - poutput->len < size_needed) {
        session->output_size_estimate = size_needed;
        return AWS_OP_SUCCESS;
    }

    struct aws_string *signature = NULL;

    int rv = aws_cryptosdk_sig_sign_finish(session->signctx, session->alloc, &signature);

    // The signature context is unconditionally destroyed, so avoid double-free
    session->signctx = NULL;

    if (rv) {
        return AWS_OP_ERR;
    }

    if (!aws_byte_buf_write_be16(poutput, signature->len) ||
        !aws_byte_buf_write_from_whole_string(poutput, signature)) {
        // Should never happen, but just in case
        rv = aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    aws_string_destroy(signature);

    if (rv == AWS_OP_SUCCESS) {
        aws_cryptosdk_priv_session_change_state(session, ST_DONE);
    }

    return rv;
}
