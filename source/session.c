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

#define DEFAULT_FRAME_SIZE (256 * 1024)
#define MAX_FRAME_SIZE 0xFFFFFFFF

static int try_encrypt_body(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
);

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
            if (session->mode != AWS_CRYPTOSDK_DECRYPT) {
                // wrong mode
                abort();
            }
            break;
        case ST_UNWRAP_KEY:
            if (session->state != ST_READ_HEADER) {
                // Illegal transition
                abort();
            }
            if (session->mode != AWS_CRYPTOSDK_DECRYPT) {
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

            // we can't currently assert that the data key is present because
            // it might be all-zero (for example)

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
            if (session->mode != AWS_CRYPTOSDK_ENCRYPT) {
                // Bad state
                abort();
            }
            // TODO check for MKP config/etc?
            break;

        case ST_WRITE_HEADER:
        {
            if (session->mode != AWS_CRYPTOSDK_ENCRYPT) {
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

int aws_cryptosdk_session_reset(struct aws_cryptosdk_session *session, enum aws_cryptosdk_mode mode) {
    if (session->header_copy) {
        aws_cryptosdk_secure_zero(session->header_copy, session->header_size);
        aws_mem_release(session->alloc, session->header_copy);
    }

    session->header_copy = NULL;
    session->header_size = 0;

    aws_cryptosdk_hdr_clean_up(session->alloc, &session->header);

    /* Stash the state we want to keep and zero the rest */
    struct aws_allocator *alloc = session->alloc;
    size_t frame_size = session->frame_size;
    aws_cryptosdk_secure_zero(session, sizeof(*session));
    session->alloc = alloc;
    session->frame_size = frame_size;
    session->mode = mode;

    session->input_size_estimate = session->output_size_estimate = 1;
    session->size_bound = UINT64_MAX;

    if (mode != AWS_CRYPTOSDK_ENCRYPT && mode != AWS_CRYPTOSDK_DECRYPT) {
        return fail_session(session, AWS_ERROR_UNIMPLEMENTED);
    }

    return AWS_OP_SUCCESS;
}

static void encrypt_compute_body_estimate(struct aws_cryptosdk_session *session) {
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

struct aws_cryptosdk_session *aws_cryptosdk_session_new(
    struct aws_allocator *allocator,
    enum aws_cryptosdk_mode mode
) {
    struct aws_cryptosdk_session *session = aws_mem_acquire(allocator, sizeof(struct aws_cryptosdk_session));

    if (!session) {
        return NULL;
    }

    aws_cryptosdk_secure_zero(session, sizeof(*session));

    session->alloc = allocator;
    session->frame_size = DEFAULT_FRAME_SIZE;

    // This can fail due to invalid mode
    if (aws_cryptosdk_session_reset(session, mode)) {
        aws_mem_release(allocator, session);
        return NULL;
    }

    return session;
}

void aws_cryptosdk_session_destroy(struct aws_cryptosdk_session *session) {
    struct aws_allocator *alloc = session->alloc;

    aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT); // frees header arena and other dynamically allocated stuff
    aws_cryptosdk_secure_zero(session, sizeof(*session));

    aws_mem_release(alloc, session);
}

int aws_cryptosdk_session_set_frame_size(struct aws_cryptosdk_session *session, uint32_t frame_size) {
    if (session->mode != AWS_CRYPTOSDK_ENCRYPT || session->state != ST_CONFIG) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    session->frame_size = frame_size;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_session_set_message_size(
    struct aws_cryptosdk_session *session,
    uint64_t message_size
) {
    if (session->mode != AWS_CRYPTOSDK_ENCRYPT) {
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
    if (session->mode != AWS_CRYPTOSDK_ENCRYPT) {
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

    session_change_state(session, ST_UNWRAP_KEY);

    return unwrap_keys(session);
}

static int try_decrypt_body(
    struct aws_cryptosdk_session * restrict session,
    struct aws_byte_cursor * restrict poutput,
    struct aws_byte_cursor * restrict pinput
) {
    struct aws_cryptosdk_frame frame;
    // We'll save the original cursor state; if we don't have enough plaintext buffer we'll
    // need to roll back and un-consume the ciphertext.
    struct aws_byte_cursor input_rollback = *pinput;

    size_t ciphertext_size;
    size_t plaintext_size;

    if (aws_cryptosdk_deserialize_frame(&frame, &ciphertext_size, &plaintext_size,
            pinput, session->alg_props, session->frame_size)) {
        session->output_size_estimate = plaintext_size;
        session->input_size_estimate = ciphertext_size;
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
    struct aws_byte_cursor output = aws_byte_cursor_advance_nospec(poutput, plaintext_size);
    if (!output.ptr) {
        *pinput = input_rollback;
        // No progress due to not enough plaintext output space.
        return AWS_OP_SUCCESS;
    }

    // We have everything we need, try to decrypt
    int rv = aws_cryptosdk_decrypt_body(
        session->alg_props, &output, &frame.ciphertext, session->header.message_id, session->frame_seqno,
        frame.iv.ptr, &session->content_key, frame.authtag.ptr, frame.type
    );

    if (rv == AWS_ERROR_SUCCESS) {
        session->frame_seqno++;

        if (frame.type != FRAME_TYPE_FRAME) {
            session_change_state(session, ST_CHECK_TRAILER);
        }

        return rv;
    }

    // An error was encountered; the top level loop will transition to the error state
    return rv;
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


static int try_encrypt_body(
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
                if (session->mode == AWS_CRYPTOSDK_ENCRYPT) {
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
                // TODO: no-op for now, go to ST_DONE
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
                // TODO: no-op for now, go to ST_DONE
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
