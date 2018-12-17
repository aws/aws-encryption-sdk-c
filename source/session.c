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
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>

/** Public APIs and common code **/
int aws_cryptosdk_session_reset(struct aws_cryptosdk_session *session, enum aws_cryptosdk_mode mode) {
    /* session->alloc is preserved */
    session->error = 0;
    session->mode  = mode;
    session->state = ST_CONFIG;
    /* session->cmm is preserved */
    session->precise_size       = 0;
    session->size_bound         = UINT64_MAX;
    session->data_so_far        = 0;
    session->precise_size_known = false;
    session->cmm_success        = false;

    if (session->header_copy) {
        aws_secure_zero(session->header_copy, session->header_size);
        aws_mem_release(session->alloc, session->header_copy);
    }

    session->header_copy = NULL;
    session->header_size = 0;
    aws_cryptosdk_hdr_clear(&session->header);
    aws_cryptosdk_keyring_trace_clear(&session->keyring_trace);
    /* session->frame_size is preserved */
    session->input_size_estimate  = 1;
    session->output_size_estimate = 1;
    session->frame_seqno          = 0;
    session->alg_props            = NULL;
    aws_secure_zero(&session->content_key, sizeof(session->content_key));

    if (session->signctx) {
        aws_cryptosdk_sig_abort(session->signctx);
    }
    session->signctx = NULL;

    if (mode != AWS_CRYPTOSDK_ENCRYPT && mode != AWS_CRYPTOSDK_DECRYPT) {
        // We do this only after clearing all internal state, to ensure that we don't
        // accidentally leak some secret data
        return aws_cryptosdk_priv_fail_session(session, AWS_ERROR_UNIMPLEMENTED);
    }

    return AWS_OP_SUCCESS;
}

static struct aws_cryptosdk_session *aws_cryptosdk_session_new(
    struct aws_allocator *allocator, enum aws_cryptosdk_mode mode) {
    struct aws_cryptosdk_session *session = aws_mem_acquire(allocator, sizeof(struct aws_cryptosdk_session));

    if (!session) {
        return NULL;
    }

    aws_secure_zero(session, sizeof(*session));

    session->alloc      = allocator;
    session->frame_size = DEFAULT_FRAME_SIZE;

    if (aws_cryptosdk_hdr_init(&session->header, allocator)) {
        aws_mem_release(allocator, session);
        return NULL;
    }

    if (aws_cryptosdk_keyring_trace_init(allocator, &session->keyring_trace)) {
        aws_cryptosdk_hdr_clean_up(&session->header);
        aws_mem_release(allocator, session);
        return NULL;
    }

    // This can fail due to invalid mode
    if (aws_cryptosdk_session_reset(session, mode)) {
        aws_cryptosdk_hdr_clean_up(&session->header);
        aws_cryptosdk_keyring_trace_clean_up(&session->keyring_trace);
        aws_mem_release(allocator, session);
        return NULL;
    }

    return session;
}

struct aws_cryptosdk_session *aws_cryptosdk_session_new_from_cmm(
    struct aws_allocator *allocator, enum aws_cryptosdk_mode mode, struct aws_cryptosdk_cmm *cmm) {
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new(allocator, mode);

    if (session) {
        session->cmm = cmm;
        aws_cryptosdk_cmm_retain(cmm);
    }

    return session;
}

void aws_cryptosdk_session_destroy(struct aws_cryptosdk_session *session) {
    struct aws_allocator *alloc = session->alloc;

    aws_cryptosdk_session_reset(
        session, AWS_CRYPTOSDK_DECRYPT);  // frees dynamically allocated stuff (except for the header itself)

    aws_cryptosdk_hdr_clean_up(&session->header);
    aws_cryptosdk_keyring_trace_clean_up(&session->keyring_trace);
    aws_cryptosdk_cmm_release(session->cmm);

    aws_secure_zero(session, sizeof(*session));
    aws_mem_release(alloc, session);
}

int aws_cryptosdk_session_set_frame_size(struct aws_cryptosdk_session *session, uint32_t frame_size) {
    if (session->mode != AWS_CRYPTOSDK_ENCRYPT || session->state != ST_CONFIG) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    session->frame_size = frame_size;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_session_set_message_size(struct aws_cryptosdk_session *session, uint64_t message_size) {
    if (session->mode != AWS_CRYPTOSDK_ENCRYPT) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    if (session->precise_size_known) {
        // TODO AWS_BAD_STATE
        return aws_cryptosdk_priv_fail_session(session, AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    if (session->size_bound < message_size) {
        return aws_cryptosdk_priv_fail_session(session, AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    session->precise_size       = message_size;
    session->precise_size_known = true;

    if (session->state == ST_ENCRYPT_BODY) {
        aws_cryptosdk_priv_encrypt_compute_body_estimate(session);
    }

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_session_set_message_bound(struct aws_cryptosdk_session *session, uint64_t max_message_size) {
    if (session->mode != AWS_CRYPTOSDK_ENCRYPT) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    if (session->precise_size_known && session->precise_size > max_message_size) {
        return aws_cryptosdk_priv_fail_session(session, AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
    }

    if (session->size_bound > max_message_size) {
        session->size_bound = max_message_size;
    }

    return AWS_OP_SUCCESS;
}

struct aws_hash_table *aws_cryptosdk_session_get_context(struct aws_cryptosdk_session *session) {
    if ((session->mode == AWS_CRYPTOSDK_ENCRYPT && session->state == ST_CONFIG) ||
        (session->mode == AWS_CRYPTOSDK_DECRYPT &&
         (session->state == ST_DECRYPT_BODY || session->state == ST_CHECK_TRAILER || session->state == ST_DONE))) {
        return &session->header.enc_context;
    }

    aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    return NULL;
}

int aws_cryptosdk_session_process(
    struct aws_cryptosdk_session *session,
    uint8_t *outp,
    size_t outlen,
    size_t *out_bytes_written,
    const uint8_t *inp,
    size_t inlen,
    size_t *in_bytes_read) {
    struct aws_byte_buf output   = { .buffer = outp, .capacity = outlen, .len = 0 };
    struct aws_byte_cursor input = { .ptr = (uint8_t *)inp, .len = inlen };
    int result;

    enum session_state prior_state;
    const uint8_t *old_inp;
    bool made_progress;

    *out_bytes_written = 0;

    do {
        prior_state = session->state;
        old_inp     = input.ptr;

        struct aws_byte_buf remaining_space =
            aws_byte_buf_from_empty_array(output.buffer + output.len, output.capacity - output.len);

        switch (session->state) {
            case ST_CONFIG:
                if (!session->cmm) {
                    // TODO - is this the right error?
                    result = aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
                    break;
                }

                if (session->mode == AWS_CRYPTOSDK_ENCRYPT) {
                    aws_cryptosdk_priv_session_change_state(session, ST_GEN_KEY);
                } else {
                    aws_cryptosdk_priv_session_change_state(session, ST_READ_HEADER);
                }
                result = AWS_OP_SUCCESS;
                break;

            case ST_READ_HEADER: result = aws_cryptosdk_priv_try_parse_header(session, &input); break;
            case ST_UNWRAP_KEY: result = aws_cryptosdk_priv_unwrap_keys(session); break;
            case ST_DECRYPT_BODY:
                result = aws_cryptosdk_priv_try_decrypt_body(session, &remaining_space, &input);
                break;
            case ST_CHECK_TRAILER: result = aws_cryptosdk_priv_check_trailer(session, &input); break;

            case ST_GEN_KEY: result = aws_cryptosdk_priv_try_gen_key(session); break;
            case ST_WRITE_HEADER: result = aws_cryptosdk_priv_try_write_header(session, &remaining_space); break;
            case ST_ENCRYPT_BODY:
                result = aws_cryptosdk_priv_try_encrypt_body(session, &remaining_space, &input);
                break;
            case ST_WRITE_TRAILER: result = aws_cryptosdk_priv_write_trailer(session, &remaining_space); break;

            case ST_DONE: result = AWS_OP_SUCCESS; break;
            default: result = aws_raise_error(AWS_ERROR_UNKNOWN); break;
            case ST_ERROR: result = aws_raise_error(session->error); break;
        }

        made_progress = (remaining_space.len) || (input.ptr != old_inp) || (prior_state != session->state);

        output.len += remaining_space.len;
    } while (result == AWS_OP_SUCCESS && made_progress);

    *out_bytes_written = output.len;
    *in_bytes_read     = input.ptr - inp;

    if (result != AWS_OP_SUCCESS) {
        // Destroy any incomplete (and possibly corrupt) plaintext
        aws_byte_buf_secure_zero(&output);
        *out_bytes_written = 0;

        if (session->state != ST_ERROR) {
            session->error = aws_last_error();
            aws_cryptosdk_priv_session_change_state(session, ST_ERROR);
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

int aws_cryptosdk_session_get_algorithm(
    const struct aws_cryptosdk_session *session, enum aws_cryptosdk_alg_id *alg_id) {
    if (!session->alg_props) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }

    *alg_id = session->alg_props->alg_id;

    return AWS_OP_SUCCESS;
}

void aws_cryptosdk_session_estimate_buf(
    const struct aws_cryptosdk_session *AWS_RESTRICT session,
    size_t *AWS_RESTRICT outbuf_needed,
    size_t *AWS_RESTRICT inbuf_needed) {
    *outbuf_needed = session->output_size_estimate;
    *inbuf_needed  = session->input_size_estimate;
}

void aws_cryptosdk_priv_session_change_state(struct aws_cryptosdk_session *session, enum session_state new_state) {
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
        case ST_ERROR:  // fall through
        case ST_CONFIG:
            break;  // no initialization required, and we can transition from any other state

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
                abort();  // Illegal transition
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
            // TODO check for KR config/etc?
            break;

        case ST_WRITE_HEADER: {
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

        case ST_ENCRYPT_BODY: {
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
                case ST_ENCRYPT_BODY:   // ok, fall through
                case ST_DECRYPT_BODY:   // ok, fall through
                case ST_CHECK_TRAILER:  // ok, fall through
                case ST_WRITE_TRAILER:  // ok, fall through
                    break;
                default:  // Illegal transition
                    abort();
            }
            break;
    }

    session->state = new_state;
}

int aws_cryptosdk_priv_fail_session(struct aws_cryptosdk_session *session, int error_code) {
    if (session->state != ST_ERROR) {
        session->error = error_code;
        aws_cryptosdk_priv_session_change_state(session, ST_ERROR);
    }

    return aws_raise_error(error_code);
}

const struct aws_hash_table *aws_cryptosdk_session_get_enc_ctx_ptr(const struct aws_cryptosdk_session *session) {
    if (session->mode == AWS_CRYPTOSDK_DECRYPT && !session->cmm_success) {
        /* In decrypt mode, we want to wait until after CMM call to
         * return encryption context. This assures both that the
         * encryption context has already been deserialized from the
         * ciphertext and that it has already been validated, if the
         * session is using a keyring that does validation of the
         * encryption context.
         */
        return NULL;
    }
    return &session->header.enc_context;
}

struct aws_hash_table *aws_cryptosdk_session_get_enc_ctx_ptr_mut(struct aws_cryptosdk_session *session) {
    if (session->mode == AWS_CRYPTOSDK_ENCRYPT && session->state == ST_CONFIG) {
        return &session->header.enc_context;
    }
    return NULL;
}

const struct aws_array_list *aws_cryptosdk_session_get_keyring_trace_ptr(const struct aws_cryptosdk_session *session) {
    if (session->cmm_success) return &session->keyring_trace;

    return NULL;
}
