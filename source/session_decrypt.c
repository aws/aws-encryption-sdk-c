
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
#include <aws/common/string.h>
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/list_utils.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>

/** Session decrypt path routines **/

static int fill_request(struct aws_cryptosdk_dec_request *request, struct aws_cryptosdk_session *session) {
    request->alloc = session->alloc;
    request->alg   = session->alg_props->alg_id;

    size_t n_keys = aws_array_list_length(&session->header.edk_list);

    // TODO: Make encrypted_data_keys a pointer?
    if (aws_cryptosdk_edk_list_init(session->alloc, &request->encrypted_data_keys)) {
        return AWS_OP_ERR;
    }

    request->enc_ctx = &session->header.enc_ctx;

    for (size_t i = 0; i < n_keys; i++) {
        struct aws_cryptosdk_edk edk;

        if (aws_array_list_get_at(&session->header.edk_list, &edk, i)) {
            goto UNEXPECTED_ERROR;
        }
        // Because the session header owns the EDKs, clear the allocators to avoid any unfortunate double frees
        edk.provider_id.allocator   = NULL;
        edk.provider_info.allocator = NULL;
        edk.ciphertext.allocator    = NULL;

        if (aws_array_list_push_back(&request->encrypted_data_keys, &edk)) {
            goto UNEXPECTED_ERROR;
        }
    }

    return AWS_OP_SUCCESS;

UNEXPECTED_ERROR:
    aws_array_list_clean_up(&request->encrypted_data_keys);
    return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
}

static int derive_data_key(struct aws_cryptosdk_session *session, struct aws_cryptosdk_dec_materials *materials) {
    if (materials->unencrypted_data_key.len != session->alg_props->data_key_len) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    // TODO - eliminate the struct data_key type and use the unencrypted_data_key buffer directly
    struct data_key data_key = { { 0 } };
    memcpy(&data_key.keybuf, materials->unencrypted_data_key.buffer, materials->unencrypted_data_key.len);

    return aws_cryptosdk_derive_key(session->alg_props, &session->content_key, &data_key, session->header.message_id);
}

static int validate_header(struct aws_cryptosdk_session *session) {
    // Perform header validation
    int header_size    = aws_cryptosdk_hdr_size(&session->header);
    size_t authtag_len = session->alg_props->tag_len + session->alg_props->iv_len;

    if (header_size == 0) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    if (header_size - session->header.auth_len != authtag_len) {
        // The authenticated length field is wrong.
        // XXX: This is a computed field, can this actually fail in practice?
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    struct aws_byte_buf authtag = { .buffer = session->header_copy + session->header.auth_len, .len = authtag_len };
    struct aws_byte_buf headerbytebuf = { .buffer = session->header_copy, .len = session->header.auth_len };

    return aws_cryptosdk_verify_header(session->alg_props, &session->content_key, &authtag, &headerbytebuf);
}

int aws_cryptosdk_priv_unwrap_keys(struct aws_cryptosdk_session *AWS_RESTRICT session) {
    struct aws_cryptosdk_dec_request request;
    struct aws_cryptosdk_dec_materials *materials = NULL;

    session->alg_props = aws_cryptosdk_alg_props(session->header.alg_id);

    if (!session->alg_props) {
        // Unknown algorithm
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    if (fill_request(&request, session)) return AWS_OP_ERR;
    int rv = AWS_OP_ERR;

    if (aws_cryptosdk_cmm_decrypt_materials(session->cmm, &materials, &request)) goto out;

    aws_cryptosdk_transfer_list(&session->keyring_trace, &materials->keyring_trace);
    session->cmm_success = true;

    if (derive_data_key(session, materials)) goto out;
    if (validate_header(session)) goto out;

    if (session->alg_props->signature_len) {
        if (!materials->signctx) {
            aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
            goto out;
        }

        // Move ownership of the signature context out of the materials
        session->signctx   = materials->signctx;
        materials->signctx = NULL;

        // Backfill the context with the header
        if (aws_cryptosdk_sig_update(
                session->signctx, aws_byte_cursor_from_array(session->header_copy, session->header_size))) {
            goto out;
        }
    }

    session->frame_seqno = 1;
    session->frame_size  = session->header.frame_len;
    aws_cryptosdk_priv_session_change_state(session, ST_DECRYPT_BODY);

    rv = AWS_OP_SUCCESS;
out:
    if (materials) aws_cryptosdk_dec_materials_destroy(materials);
    aws_array_list_clean_up(&request.encrypted_data_keys);

    return rv;
}

int aws_cryptosdk_priv_try_parse_header(
    struct aws_cryptosdk_session *AWS_RESTRICT session, struct aws_byte_cursor *AWS_RESTRICT input) {
    const uint8_t *header_start = input->ptr;
    int rv                      = aws_cryptosdk_hdr_parse(&session->header, input);

    if (rv != AWS_OP_SUCCESS) {
        if (aws_last_error() == AWS_ERROR_SHORT_BUFFER) {
            if (input->len >= session->input_size_estimate) {
                session->input_size_estimate = input->len + 128;
                if (session->input_size_estimate < input->len) {
                    // overflow
                    session->input_size_estimate = (size_t)-1;
                }
            }
            session->output_size_estimate = 0;
            return AWS_OP_SUCCESS;  // suppress this error
        }
        return rv;
    }

    session->header_size = aws_cryptosdk_hdr_size(&session->header);

    if (session->header_size == 0) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    if ((ptrdiff_t)session->header_size != input->ptr - header_start) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    session->header_copy = aws_mem_acquire(session->alloc, session->header_size);

    if (!session->header_copy) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    memcpy(session->header_copy, header_start, session->header_size);

    aws_cryptosdk_priv_session_change_state(session, ST_UNWRAP_KEY);

    return aws_cryptosdk_priv_unwrap_keys(session);
}

int aws_cryptosdk_priv_try_decrypt_body(
    struct aws_cryptosdk_session *AWS_RESTRICT session,
    struct aws_byte_buf *AWS_RESTRICT poutput,
    struct aws_byte_cursor *AWS_RESTRICT pinput) {
    struct aws_cryptosdk_frame frame;
    // We'll save the original cursor state; if we don't have enough plaintext buffer we'll
    // need to roll back and un-consume the ciphertext.
    struct aws_byte_cursor input_rollback = *pinput;

    if (aws_cryptosdk_deserialize_frame(
            &frame,
            &session->input_size_estimate,
            &session->output_size_estimate,
            pinput,
            session->alg_props,
            session->frame_size)) {
        if (aws_last_error() == AWS_ERROR_SHORT_BUFFER) {
            // Not actually an error. We've updated the estimates, so move on.
            return AWS_OP_SUCCESS;
        } else {
            // Frame format was malformed. Propagate the error up the chain.
            return AWS_OP_ERR;
        }
    }

    // The frame is structurally sound. Now we just need to do some validation of its
    // contents and decrypt.

    if (session->frame_seqno != frame.sequence_number) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    // Before we go further, do we have enough room to place the plaintext?
    struct aws_byte_buf output;
    aws_byte_buf_init(&output, aws_default_allocator(), session->output_size_estimate);
    if (!aws_byte_buf_advance(poutput, &output, session->output_size_estimate)) {
        *pinput = input_rollback;
        // No progress due to not enough plaintext output space.
        return AWS_OP_SUCCESS;
    }

    // XXX: There is a condition where plaintext length is 0, so the ciphertext length and
    // capacity estimates are 0, and the buffer len and capacity get set to 0. However, the
    // ciphertext.buffer still points to a block of memory. This causes the precondition
    // for aws_byte_cursor_from_buf to fail. Setting the buffer to NULL fixes this, passes
    // all the tests, and seems horribly hacky and wrong.
    if (frame.ciphertext.len == 0 && frame.ciphertext.capacity == 0) {
        frame.ciphertext.buffer = NULL;
    }

    // We have everything we need, try to decrypt
    struct aws_byte_cursor ciphertext_cursor = aws_byte_cursor_from_buf(&frame.ciphertext);
    int rv                                   = aws_cryptosdk_decrypt_body(
        session->alg_props,
        &output,
        &ciphertext_cursor,
        session->header.message_id,
        frame.sequence_number,
        frame.iv.buffer,
        &session->content_key,
        frame.authtag.buffer,
        frame.type);

    if (rv == AWS_ERROR_SUCCESS) {
        session->frame_seqno++;

        if (session->signctx) {
            struct aws_byte_cursor frame = { .ptr = input_rollback.ptr, .len = pinput->ptr - input_rollback.ptr };
            if (aws_cryptosdk_sig_update(session->signctx, frame)) {
                return AWS_OP_ERR;
            }
        }

        if (frame.type != FRAME_TYPE_FRAME) {
            aws_cryptosdk_priv_session_change_state(session, ST_CHECK_TRAILER);
        }

        return rv;
    }

    // An error was encountered; the top level loop will transition to the error state
    return rv;
}

int aws_cryptosdk_priv_check_trailer(
    struct aws_cryptosdk_session *AWS_RESTRICT session, struct aws_byte_cursor *AWS_RESTRICT input) {
    /* By the time we're here, we're not going to provide any more output.
     * We might need more input, and if so we'll update input_size_estimate
     * below. For now we'll set it to zero so that when session is
     * done both estimates will be zero.
     */
    session->output_size_estimate = 0;
    session->input_size_estimate  = 0;

    struct aws_byte_cursor initial_input = *input;
    if (session->signctx == NULL) {
        aws_cryptosdk_priv_session_change_state(session, ST_DONE);
        return AWS_OP_SUCCESS;
    }

    uint16_t sig_len = 0;
    struct aws_byte_cursor signature;
    if (!aws_byte_cursor_read_be16(input, &sig_len) ||
        !(signature = aws_byte_cursor_advance_nospec(input, sig_len)).ptr) {
        // Not enough data to read the signature yet
        session->input_size_estimate = 2 + sig_len;
        *input                       = initial_input;
        return AWS_OP_SUCCESS;
    }

    // TODO: should the signature be a cursor after all?
    struct aws_string *signature_str = aws_string_new_from_array(session->alloc, signature.ptr, signature.len);
    if (!signature_str) {
        return AWS_OP_ERR;
    }
    int rv = aws_cryptosdk_sig_verify_finish(session->signctx, signature_str);

    // signctx is unconditionally freed, so avoid double free by nulling it out
    session->signctx = NULL;
    aws_string_destroy(signature_str);

    return rv;
}
