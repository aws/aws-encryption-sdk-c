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
#include <aws/common/byte_buf.h>

#define DEFAULT_FRAME_SIZE (256 * 1024)
#define MAX_FRAME_SIZE 0xFFFFFFFF

static void session_change_state(struct aws_cryptosdk_session *session, enum session_state new_state) {
    // Performs internal sanity checks before allowing a state change.

    // Since the intent is mostly to avoid use of initialized memory due to internal bugs, we
    // simply abort if something went wrong.
    // We can change this to enter an error state instead in the future if necessary.
    if (session->state == new_state) {
        // no-op
        return;
    }

    if (session->state == ST_ERROR) {
        // Can't leave ST_ERROR except by reinitializing
        if (new_state != ST_CONFIG) {
            abort();
        }
    }

    switch (new_state) {
        case ST_ERROR: // fall through
        case ST_CONFIG:
            break; // no initialization required, and we can transition from any other state

        /***** Decrypt path *****/

        case ST_READ_HEADER:
            if (session->state != ST_CONFIG) {
                // Illegal transition
                abort();
            }
            if (session->mode != MODE_DECRYPT) {
                // wrong mode
                abort();
            }
            break;
        case ST_UNWRAP_KEY:
            if (session->state != ST_READ_HEADER) {
                // Illegal transition
                abort();
            }
            if (session->mode != MODE_DECRYPT) {
                // wrong mode
                abort();
            }
            // check that a few of the more important state values are configured
            if (!session->header_copy || !session->header_size) {
                abort();
            }
            break;

        case ST_DECRYPT_BODY:
            if (session->state != ST_UNWRAP_KEY) {
                // Illegal transition
                break;
            }

            if (!session->alg_props) {
                // algorithm properties not set
                abort();
            }

            if (session->frame_seqno == 0) {
                // illegal sequence number
                abort();
            }

            // we can't currently assert that the data key is present because, well, it might be all-zero
            break;

        case ST_CHECK_TRAILER:
            if (session->state != ST_DECRYPT_BODY) {
                abort(); // Illegal transition
            }
            break;

        /***** Encrypt path *****/

        case ST_GEN_KEY:
            if (session->state != ST_CONFIG) {
                // illegal transition
                abort();
            }
            if (session->mode != MODE_ENCRYPT) {
                // Bad state
                abort();
            }
            // TODO check for MKP config/etc?
            break;

        case ST_WRITE_HEADER:
        {
            if (session->mode != MODE_ENCRYPT) {
                // wrong mode
                abort();
            }

            if (ST_GEN_KEY != session->state) {
                // Illegal transition
                abort();
            }

            // We should have generated the header, and should now be ready to write it.
            if (!session->header_copy || !session->header_size) {
                abort();
            }
            break;
        }

        case ST_ENCRYPT_BODY:
        {
            if (ST_WRITE_HEADER != session->state) {
                // Illegal transition
                abort();
            }

            if (!session->alg_props) {
                // algorithm properties not set
                abort();
            }

            if (session->frame_seqno == 0) {
                // illegal sequence number
                abort();
            }

            // we can't currently assert that the data key is present because, well, it might be all-zero
            break;
        }

        case ST_WRITE_TRAILER:
            if (session->state != ST_ENCRYPT_BODY) {
                // illegal transition
                abort();
            }
            break;

        case ST_DONE:
            switch (session->state) {
                case ST_ENCRYPT_BODY: // ok, fall through
                case ST_DECRYPT_BODY: // ok, fall through
                case ST_CHECK_TRAILER: // ok, fall through
                case ST_WRITE_TRAILER: // ok, fall through
                    break;
                default: // Illegal transition
                    abort();
            }
            break;
    }

    session->state = new_state;
}

static int fail_session(struct aws_cryptosdk_session *session, int error_code) {
    if (session->state != ST_ERROR) {
        session->error = error_code;
        session_change_state(session, ST_ERROR);
    }

    return aws_raise_error(error_code);
}

static void session_reset(struct aws_cryptosdk_session *session) {
    if (session->header_copy) {
        aws_cryptosdk_secure_zero(session->header_copy, session->header_size);
        aws_mem_release(session->alloc, session->header_copy);
    }
    aws_cryptosdk_hdr_free(session->alloc, &session->header);

    /* Stash the state we want to keep and zero the rest */
    struct aws_allocator *alloc = session->alloc;
    aws_cryptosdk_secure_zero(session, sizeof(*session));
    session->alloc = alloc;

    session->input_size_estimate = session->output_size_estimate = 1;
}

static void encrypt_compute_body_estimate(struct aws_cryptosdk_session *session) {
    size_t authtag_len = session->alg_props->tag_len + session->alg_props->iv_len;

    if (session->state != ST_ENCRYPT_BODY) {
        /* Not our job to set the estimates */
    }

    if (session->frame_size) {
        /* framed message */
        if (session->precise_size_known) {
            uint64_t remaining = session->precise_size - session->data_so_far;
            if (remaining < session->frame_size) {
                /* last frame */
                session->input_size_estimate = remaining;
                session->output_size_estimate =
                    /* final frame size */
                    4 + /* end mark */
                    4 + /* seqno */
                    session->alg_props->iv_len +
                    4 + /* encrypted content len */
                    remaining +
                    authtag_len;

                return;
            }
            /* If not final frame, fall through to the unknown size case */
        }

        /* If not final frame, or unknown size, we'll estimate enough to fill another frame */
        session->input_size_estimate = session->frame_size;
        session->output_size_estimate =
            4 + /* seqno */
            session->alg_props->iv_len +
            session->frame_size +
            authtag_len;
    } else {
        /* non-framed message */
        if (!session->precise_size_known) {
            /* Can't process any data until we know the message size */
            session->input_size_estimate = session->output_size_estimate = 0;
            return;
        } else {
            session->input_size_estimate = session->precise_size;
            session->output_size_estimate =
                session->alg_props->iv_len +
                8 + /* encrypted content length */
                session->precise_size +
                authtag_len;
        }
    }
}

struct aws_cryptosdk_session *aws_cryptosdk_session_new(
    struct aws_allocator *allocator
) {
    struct aws_cryptosdk_session *session = aws_mem_acquire(allocator, sizeof(struct aws_cryptosdk_session));

    if (!session) {
        return NULL;
    }

    aws_cryptosdk_secure_zero(session, sizeof(*session));

    session->alloc = allocator;
    session_reset(session);

    return session;
}

void aws_cryptosdk_session_destroy(struct aws_cryptosdk_session *session) {
    struct aws_allocator *alloc = session->alloc;

    session_reset(session); // frees header arena and other dynamically allocated stuff
    aws_cryptosdk_secure_zero(session, sizeof(*session));

    aws_mem_release(alloc, session);
}

int aws_cryptosdk_session_init_decrypt(struct aws_cryptosdk_session *session) {
    session_reset(session);
    session->mode = MODE_DECRYPT;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_session_init_encrypt(struct aws_cryptosdk_session *session) {
    session_reset(session);
    session->mode = MODE_ENCRYPT;

    session->size_bound = (uint64_t)-1;
    session->frame_size = DEFAULT_FRAME_SIZE;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_session_set_frame_size(struct aws_cryptosdk_session *session, size_t frame_size) {
    if (session->mode != MODE_ENCRYPT || session->state != ST_CONFIG) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    if (frame_size > MAX_FRAME_SIZE) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    session->frame_size = frame_size;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_session_set_message_size(
    struct aws_cryptosdk_session *session,
    uint64_t message_size
) {
    if (session->mode != MODE_ENCRYPT) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    if (session->precise_size_known) {
        // TODO AWS_BAD_STATE
        return fail_session(session, AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    if (session->size_bound < message_size) {
        return fail_session(session, AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    session->precise_size = message_size;
    session->precise_size_known = true;

    if (session->state == ST_ENCRYPT_BODY) {
        encrypt_compute_body_estimate(session);
    }

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_session_set_message_bound(
    struct aws_cryptosdk_session *session,
    uint64_t max_message_size
) {
    if (session->mode != MODE_ENCRYPT) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    if (session->precise_size_known && session->precise_size > max_message_size) {
        return fail_session(session, AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    if (session->size_bound > max_message_size) {
        session->size_bound = max_message_size;
    }

    return AWS_OP_SUCCESS;
}

static int unwrap_keys(
    struct aws_cryptosdk_session * restrict session
) {
    // TODO - use CMM/MKP to get the data key.
    // For now we'll just use an all-zero key to expedite testing
    struct data_key data_key = { { 0 } };

    uint16_t alg_id = session->header.alg_id;
    session->alg_props = aws_cryptosdk_alg_props(alg_id);

    if (!session->alg_props) {
        // Unknown algorithm
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
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

    // Perform header validation
    int header_size = aws_cryptosdk_hdr_size(&session->header);
    size_t authtag_len = session->alg_props->tag_len + session->alg_props->iv_len;

    if (header_size - session->header.auth_len != authtag_len) {
        // The authenticated length field is wrong.
        // XXX: This is a computed field, can this actually fail in practice?
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    struct aws_byte_buf authtag = { .buffer = session->header_copy + session->header.auth_len, .len = authtag_len };
    struct aws_byte_buf headerbytebuf = { .buffer = session->header_copy, .len = session->header.auth_len };

    int err = aws_cryptosdk_verify_header(session->alg_props, &session->content_key, &authtag, &headerbytebuf);

    if (err) {
        return err;
    }

    session->frame_seqno = 1;
    session->frame_size = session->header.frame_len;
    session_change_state(session, ST_DECRYPT_BODY);

    return AWS_OP_SUCCESS;
}

static int try_parse_header(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict input
) {
    int rv = aws_cryptosdk_hdr_parse(session->alloc, &session->header, input->ptr, input->len);

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
            return AWS_OP_SUCCESS; // suppress this error
        }
        return rv;
    }

    session->header_size = aws_cryptosdk_hdr_size(&session->header);
    session->header_copy = aws_mem_acquire(session->alloc, session->header_size);

    if (!session->header_copy) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    memcpy(session->header_copy, input->ptr, session->header_size);

    aws_byte_cursor_advance(input, session->header_size);

    session_change_state(session, ST_UNWRAP_KEY);

    return unwrap_keys(session);
}

static int try_decrypt_body(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
) {
    size_t frame_len = session->frame_size;
    // TODO expose type into session->header and use this for is_framed determination
    bool is_framed = frame_len != 0;

    int tag_len = session->alg_props->tag_len;
    int iv_len  = session->alg_props->iv_len;
    int body_frame_type;

    uint32_t seqno;

    size_t output_len = 0;
    size_t input_len = 0;

    struct aws_byte_cursor input = *pinput;

    struct aws_byte_cursor iv;
    struct aws_byte_cursor content;
    struct aws_byte_cursor tag;

    if (is_framed) {
        input_len = 4;
        if (!aws_byte_cursor_read_be32(&input, &seqno)) {
            goto no_progress;
        }

        if (seqno != 0xFFFFFFFF) {
            // Not final frame
            body_frame_type = FRAME_TYPE_FRAME;
            output_len = frame_len;
            input_len += frame_len + iv_len + tag_len;

            if (!(iv = aws_byte_cursor_advance(&input, iv_len)).ptr) goto no_progress;
            if (!(content = aws_byte_cursor_advance(&input, frame_len)).ptr) goto no_progress;
            if (!(tag = aws_byte_cursor_advance(&input, tag_len)).ptr) goto no_progress;
        } else {
            // Final frame
            body_frame_type = FRAME_TYPE_FINAL;

            // Read the true sequence number after the final-frame sentinel
            input_len += 4; // 32-bit field read
            if (!aws_byte_cursor_read_be32(&input, &seqno)) goto no_progress;

            input_len += iv_len;
            if (!(iv = aws_byte_cursor_advance(&input, iv_len)).ptr) goto no_progress;

            uint32_t content_len;
            input_len += 4; // 32-bit field read
            if (!aws_byte_cursor_read_be32(&input, &content_len)) goto no_progress;

            input_len += content_len + tag_len;
            output_len = content_len;

            if (!(content = aws_byte_cursor_advance_nospec(&input, content_len)).ptr) goto no_progress;
            if (!(tag = aws_byte_cursor_advance_nospec(&input, tag_len)).ptr) goto no_progress;
        }

        // Sanity checks
        if (content.len > frame_len) {
            return AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT;
        }
    } else {
        body_frame_type = FRAME_TYPE_SINGLE;

        input_len += iv_len;
        if (!(iv = aws_byte_cursor_advance(&input, iv_len)).ptr) goto no_progress;

        uint64_t content_len;
        input_len += 8; // 64-bit field read
        if (!aws_byte_cursor_read_be64(&input, &content_len)) goto no_progress;

        output_len = content_len;
        input_len += content_len + tag_len;

        if (!(content = aws_byte_cursor_advance_nospec(&input, content_len)).ptr) goto no_progress;
        if (!(tag = aws_byte_cursor_advance_nospec(&input, tag_len)).ptr) goto no_progress;

        seqno = 1; // not actually present, but fix it up for validation below
    }

    if (session->frame_seqno != seqno) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    // At this point iv, tag, content, body_frame_type are initialized
    struct aws_byte_cursor output = aws_byte_cursor_advance_nospec(poutput, output_len);
    if (!output.ptr) goto no_progress;

    // We have everything we need, try to decrypt
    int rv = aws_cryptosdk_decrypt_body(
        session->alg_props, &output, &content, session->header.message_id, session->frame_seqno,
        iv.ptr, &session->content_key, tag.ptr, body_frame_type
    );

    if (rv == AWS_ERROR_SUCCESS) {
        session->frame_seqno++;
        *pinput = input;

        if (body_frame_type != FRAME_TYPE_FRAME) {
            session_change_state(session, ST_CHECK_TRAILER);
        }

        return rv;
    }

    // An error was encountered; the top level loop will transition to the error state
    return rv;

no_progress:        
    session->input_size_estimate = input.ptr - pinput->ptr;
    if (input_len > session->input_size_estimate) {
        session->input_size_estimate = input_len;
    }

    session->output_size_estimate = output_len;

    return AWS_ERROR_SUCCESS;
}

int try_gen_key(
    struct aws_cryptosdk_session *session
) {
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

    edk->provider_id = aws_byte_buf_from_literal("null");
    edk->provider_info = aws_byte_buf_from_literal("null");
    edk->enc_data_key = aws_byte_buf_from_literal("");

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

static uint8_t *place_iv(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput
) {
    return aws_byte_cursor_advance(poutput, session->alg_props->iv_len).ptr;
}


static int try_encrypt_body_full(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
) {
    if (!session->precise_size_known) {
        // Can't do anything until we know the body size.
        session->input_size_estimate = session->output_size_estimate = 1;
        return AWS_OP_SUCCESS;
    }

    // We need the entire input in a single chunk
    size_t input_needed = session->precise_size;
    size_t output_size = session->alg_props->iv_len +
            8 + /* encrypted content length */
            input_needed +
            session->alg_props->tag_len;

    session->input_size_estimate = input_needed;
    session->output_size_estimate = output_size;

    if (pinput->len < input_needed || poutput->len < output_size) {
        return AWS_OP_SUCCESS;
    }

    // Preserve the output cursor so we can clear it on failure
    struct aws_byte_cursor output_original = *poutput;

    uint8_t *iv = place_iv(session, poutput);
    if (!iv) {
        // We already checked the buffer sizes; this should be impossible, but just in case...
        goto unknown_error;
    }

    uint64_t length = aws_hton64(input_needed);
    if (aws_byte_cursor_write(poutput, (const uint8_t *)&length, sizeof(length))) {
        goto unknown_error;
    }

    struct aws_byte_cursor ciphertext = aws_byte_cursor_advance(poutput, input_needed);
    struct aws_byte_cursor authtag    = aws_byte_cursor_advance(poutput, session->alg_props->tag_len);
    struct aws_byte_cursor plaintext  = aws_byte_cursor_advance(pinput, input_needed);

    if (!ciphertext.ptr || !plaintext.ptr) {
        goto unknown_error;
    }

    if (aws_cryptosdk_encrypt_body(
        session->alg_props,
        &ciphertext,
        &plaintext,
        session->header.message_id,
        1,
        iv,
        &session->content_key,
        authtag.ptr,
        FRAME_TYPE_SINGLE
    )) {
        goto error;
    }

    session_change_state(session, ST_WRITE_TRAILER);

    return AWS_OP_SUCCESS;

unknown_error:
    aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
error:
    aws_cryptosdk_secure_zero(output_original.ptr, output_original.len);
    return AWS_OP_ERR;
}

static int try_encrypt_intermediate_frame(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
) {
    // Preserve the output cursor so we can clear it on failure
    struct aws_byte_cursor output_original = *poutput;

    size_t input_needed = session->frame_size;
    size_t output_size = 4 + /* seqno */
        session->alg_props->iv_len +
        input_needed +
        session->alg_props->tag_len;

    if (session->frame_seqno == 0xFFFFFFFF) {
        // We've already encrypted the maximum number of intermediate frames. Refuse to encrypt any more
        // until the precise size is given
        if (!session->precise_size_known) {
            session->input_size_estimate = session->output_size_estimate = 1;
            return AWS_OP_SUCCESS;
        } else {
            // Whoops, the body is too big to encrypt with this frame size.
            return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
        }
    }

    session->input_size_estimate = input_needed;
    session->output_size_estimate = output_size;

    if (pinput->len < input_needed || poutput->len < output_size) {
        return AWS_OP_SUCCESS;
    }

    if (!aws_byte_cursor_write_be32(poutput, session->frame_seqno)) {
        // We already checked that we had enough space, but out of paranoia
        // we'll check returns.
        goto unknown_error;
    }

    uint8_t *iv = place_iv(session, poutput);

    struct aws_byte_cursor ciphertext = aws_byte_cursor_advance(poutput, input_needed);
    struct aws_byte_cursor authtag    = aws_byte_cursor_advance(poutput, session->alg_props->tag_len);
    struct aws_byte_cursor plaintext  = aws_byte_cursor_advance(pinput, input_needed);

    if (!ciphertext.ptr || !authtag.ptr || !plaintext.ptr) {
        goto unknown_error;
    }

    if (aws_cryptosdk_encrypt_body(
        session->alg_props,
        &ciphertext,
        &plaintext,
        session->header.message_id,
        session->frame_seqno,
        iv,
        &session->content_key,
        authtag.ptr,
        FRAME_TYPE_FRAME
    )) {
        goto error;
    }

    session->frame_seqno++;
    session->data_so_far += input_needed;

    return AWS_OP_SUCCESS;

unknown_error:
    aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);

error:
    aws_cryptosdk_secure_zero(output_original.ptr, output_original.len);

    return AWS_OP_ERR;
}

static int try_encrypt_last_frame(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
) {
    // Preserve the output cursor so we can clear it on failure
    struct aws_byte_cursor output_original = *poutput;

    uint64_t input_needed = session->precise_size - session->data_so_far;
    uint64_t output_size   = 4 + /* end frame marker */
        4 + /* sequence number */
        session->alg_props->iv_len +
        4 + /* encrypted content length */
        input_needed +
        session->alg_props->tag_len;

    if (!session->precise_size_known || input_needed > session->frame_size) {
        // Should never happen (these should be checked in try_encrypt_body)
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    if (input_needed > 0xFFFFFFFFULL) {
        // Should be impossible (due to frame size restrictions)
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    session->input_size_estimate = input_needed;
    session->output_size_estimate = output_size;

    if (poutput->len < output_size || pinput->len < input_needed) {
        // Not enough input/output space, do nothing for now
        return AWS_OP_SUCCESS;
    }

    if (!aws_byte_cursor_write_be32(poutput, 0xFFFFFFFF)) {
        // Should never happen, since we already checked the output buffer size
        goto unknown_error;
    }

    if (!aws_byte_cursor_write_be32(poutput, session->frame_seqno)) goto unknown_error;
    uint8_t *iv = place_iv(session, poutput);
    if (!aws_byte_cursor_write_be32(poutput, input_needed)) goto unknown_error;

    struct aws_byte_cursor ciphertext = aws_byte_cursor_advance(poutput, input_needed);
    struct aws_byte_cursor authtag    = aws_byte_cursor_advance(poutput, session->alg_props->tag_len);
    struct aws_byte_cursor plaintext  = aws_byte_cursor_advance(pinput, input_needed);

    if (aws_cryptosdk_encrypt_body(
        session->alg_props,
        &ciphertext,
        &plaintext,
        session->header.message_id,
        session->frame_seqno,
        iv,
        &session->content_key,
        authtag.ptr,
        FRAME_TYPE_FINAL
    )) {
        goto error;
    }

    session_change_state(session, ST_WRITE_TRAILER);

    return AWS_OP_SUCCESS;

unknown_error:
    aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);

error:
    aws_cryptosdk_secure_zero(output_original.ptr, output_original.len);

    return AWS_OP_ERR;
}

static int try_encrypt_body(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
) {
    if (session->frame_size == 0) {
        return try_encrypt_body_full(session, poutput, pinput);
    } else if (session->precise_size_known
        && session->data_so_far + session->frame_size >= session->precise_size) {
        // Last frame
        return try_encrypt_last_frame(session, poutput, pinput);
    } else {
        // Not last frame
        return try_encrypt_intermediate_frame(session, poutput, pinput);
    }
}

int aws_cryptosdk_session_process(
    struct aws_cryptosdk_session * restrict session,
    uint8_t *outp, size_t outlen, size_t *out_bytes_written,
    const uint8_t *inp, size_t inlen, size_t *in_bytes_read
) {

    struct aws_byte_cursor output = { .ptr = outp, .len = outlen };
    struct aws_byte_cursor input  = { .ptr = (uint8_t *)inp, .len =  inlen };
    int result;

    enum session_state prior_state;
    const uint8_t *old_outp, *old_inp;
    bool made_progress;

    do {
        prior_state = session->state;
        old_outp = output.ptr;
        old_inp = input.ptr;

        switch (session->state) {
            case ST_CONFIG:
                // TODO: Verify mandatory config is present
                // Right now we haven't implemented CMMs yet, so this is a no-op
                if (session->mode == MODE_ENCRYPT) {
                    session_change_state(session, ST_GEN_KEY);
                } else {
                    session_change_state(session, ST_READ_HEADER);
                }
                result = AWS_OP_SUCCESS;
                break;

            case ST_READ_HEADER:
                result = try_parse_header(session, &input);
                break;
            case ST_UNWRAP_KEY:
                result = unwrap_keys(session);
                break;
            case ST_DECRYPT_BODY:
                result = try_decrypt_body(session, &output, &input);
                break;
            case ST_CHECK_TRAILER:
                // no-op for now, go to ST_DONE
                session_change_state(session, ST_DONE);
                result = AWS_OP_SUCCESS;
                break;

            case ST_GEN_KEY:
                result = try_gen_key(session);
                break;
            case ST_WRITE_HEADER:
                result = try_write_header(session, &output);
                break;
            case ST_ENCRYPT_BODY:
                result = try_encrypt_body(session, &output, &input);
                break;
            case ST_WRITE_TRAILER:
                // no-op for now, go to ST_DONE
                session_change_state(session, ST_DONE);
                result = AWS_OP_SUCCESS;
                break;

            case ST_DONE:
                result = AWS_OP_SUCCESS;
                break;
            default:
                result = aws_raise_error(AWS_ERROR_UNKNOWN);
                break;
            case ST_ERROR:
                result = aws_raise_error(session->error);
                break;
        }

        made_progress = (output.ptr != old_outp) || (input.ptr != old_inp) || (prior_state != session->state);
    } while (result == AWS_OP_SUCCESS && made_progress);

    *out_bytes_written = output.ptr - outp;
    *in_bytes_read = input.ptr - inp;

    if (result != AWS_OP_SUCCESS) {
        // Destroy any incomplete (and possibly corrupt) plaintext
        aws_cryptosdk_secure_zero(outp, outlen);
        *out_bytes_written = 0;

        if (session->state != ST_ERROR) {
            session->error = aws_last_error();
            session_change_state(session, ST_ERROR);
        }
    }

    if (session->state == ST_ERROR) {
        // (Re-)raise any stored error
        result = aws_raise_error(session->error);
    }

    return result;
}

bool aws_cryptosdk_session_is_done(const struct aws_cryptosdk_session *session) {
    return session->state == ST_DONE;
}

void aws_cryptosdk_session_estimate_buf(
    const struct aws_cryptosdk_session * restrict session,
    size_t * restrict outbuf_needed,
    size_t * restrict inbuf_needed
) {
    *outbuf_needed = session->output_size_estimate;
    *inbuf_needed = session->input_size_estimate;
}
