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

#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/session.h>

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
        case ST_HEADER:
            if (session->state != ST_CONFIG) {
                // illegal transition
                abort();
            }
            if (session->mode != MODE_ENCRYPT && session->mode != MODE_DECRYPT) {
                // unknown mode
                abort();
            }
            // no particular initialization required (on decrypt)
            // for encrypt we'll need to do some more asserts here
            break;
        case ST_KEYING:
            if (session->state != ST_HEADER) {
                // illegal transition
                abort();
            }
            // check that a few of the more important state values are configured
            if (!session->header_copy || !session->header_size) {
                abort();
            }
            break;
        case ST_BODY:
            if (session->state != ST_KEYING) {
                // illegal transition
                abort();
            }
            if (!session->alg_props) {
                // algorithm properties not set
                abort();
            }
            // we can't currently assert that the data key is present because, well, it might be all-zero
            break;
        case ST_TRAILER:
            if (session->state != ST_BODY) {
                // illegal transition
                abort();
            }
            break;
        case ST_DONE:
            if (session->state != ST_BODY && session->state != ST_TRAILER) {
                // illegal transition
                abort();
            }
            break;
    }

    session->state = new_state;
}

static void session_reset(struct aws_cryptosdk_session *session) {
    if (session->header_copy) {
        aws_cryptosdk_secure_zero(session->header_copy, session->header_size);
        aws_mem_release(session->alloc, session->header_copy);
    }
    session->header_copy = NULL;
    session->header_size = 0;

    aws_cryptosdk_hdr_clean_up(session->alloc, &session->header);

    aws_cryptosdk_secure_zero(&session->content_key, sizeof(session->content_key));

    session->mode = MODE_UNINIT;
    session_change_state(session, ST_CONFIG);
    session->state = ST_CONFIG;
    session->error = 0;
    session->frame_seqno = 0;
    session->input_size_estimate = 1;
    session->output_size_estimate = 0;
    session->alg_props = NULL;
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

static int init_keys(
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

    session_change_state(session, ST_BODY);
    session->frame_seqno = 1;

    return AWS_OP_SUCCESS;


}

static int try_parse_header(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict input
) {
    int rv = aws_cryptosdk_hdr_parse_init(session->alloc, &session->header, input->ptr, input->len);

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

    session_change_state(session, ST_KEYING);

    return init_keys(session);
}

static int try_process_body(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
) {
    size_t frame_len = session->header.frame_len;
    // TODO expose type into session->header and use this for is_framed determination
    bool is_framed = frame_len != 0;

    int tag_len = session->alg_props->tag_len;
    int iv_len  = session->alg_props->iv_len;
    int body_frame_type;

    size_t output_len = 0;
    size_t input_len = 0;

    struct aws_byte_cursor input = *pinput;

    struct aws_byte_cursor iv;
    struct aws_byte_cursor content;
    struct aws_byte_cursor tag;

    if (is_framed) {
        uint32_t seqno;
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

        if (seqno != session->frame_seqno) {
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
            session_change_state(session, ST_TRAILER);
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
                session_change_state(session, ST_HEADER);
                // fall through
            case ST_HEADER:
                result = try_parse_header(session, &input);
                break;
            case ST_KEYING:
                result = init_keys(session);
                break;
            case ST_BODY:
                result = try_process_body(session, &output, &input);
                break;
            case ST_TRAILER:
                // no-op for now, go to ST_DONE
                session_change_state(session, ST_DONE);
                // fall through
            case ST_DONE:
                result = AWS_OP_SUCCESS;
                break;
            default:
                result = aws_raise_error(AWS_ERROR_UNKNOWN);
                // fall through
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
