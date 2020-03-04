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

#ifndef AWS_CRYPTOSDK_PRIVATE_SESSION_H
#define AWS_CRYPTOSDK_PRIVATE_SESSION_H

#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/session.h>

#define DEFAULT_FRAME_SIZE (256 * 1024)

enum session_state {
    /*** Common states ***/

    /* State ST_CONFIG: Initial configuration. No data has been supplied */
    ST_CONFIG = 0,
    /* State ST_ERROR: De/encryption failure. No data will be processed until reset */
    ST_ERROR,
    ST_DONE,

    /*** Decrypt path ***/

    ST_READ_HEADER,
    ST_UNWRAP_KEY,
    ST_DECRYPT_BODY,
    ST_CHECK_TRAILER,

    /*** Encrypt path ***/

    ST_GEN_KEY,
    ST_WRITE_HEADER,
    ST_ENCRYPT_BODY,
    ST_WRITE_TRAILER,
};

struct aws_cryptosdk_session {
    struct aws_allocator *alloc;
    int error;
    enum aws_cryptosdk_mode mode;
    enum session_state state;

    struct aws_cryptosdk_cmm *cmm;

    /* Encrypt mode configuration */
    uint64_t precise_size; /* Exact size of message */
    uint64_t size_bound;   /* Maximum message size */
    uint64_t data_so_far;  /* Bytes processed thus far */
    bool precise_size_known;

    /* The actual header, if parsed */
    uint8_t *header_copy;
    size_t header_size;
    struct aws_cryptosdk_hdr header;
    uint64_t frame_size; /* Frame size, zero for unframed */

    /* List of (struct aws_cryptosdk_keyring_trace_record)s */
    struct aws_array_list keyring_trace;

    /* Estimate for the amount of input data needed to make progress. */
    size_t input_size_estimate;

    /* Estimate for the amount of output buffer needed to make progress. */
    size_t output_size_estimate;

    uint64_t frame_seqno;

    const struct aws_cryptosdk_alg_properties *alg_props;

    /* Decrypted, derived (if applicable) content key */
    struct content_key content_key;

    /* In-progress trailing signature context (if applicable) */
    struct aws_cryptosdk_sig_ctx *signctx;

    /* Set to true after successful call to CMM to indicate availability
     * of keyring trace and--in the case of decryption--the encryption context.
     */
    bool cmm_success;
};

/* Common session routines */

void aws_cryptosdk_priv_session_change_state(struct aws_cryptosdk_session *session, enum session_state new_state);
int aws_cryptosdk_priv_fail_session(struct aws_cryptosdk_session *session, int error_code);

/* Decrypt path */
int aws_cryptosdk_priv_unwrap_keys(struct aws_cryptosdk_session *AWS_RESTRICT session);
int aws_cryptosdk_priv_try_parse_header(
    struct aws_cryptosdk_session *AWS_RESTRICT session, struct aws_byte_cursor *AWS_RESTRICT input);
int aws_cryptosdk_priv_try_decrypt_body(
    struct aws_cryptosdk_session *AWS_RESTRICT session,
    struct aws_byte_buf *AWS_RESTRICT poutput,
    struct aws_byte_cursor *AWS_RESTRICT pinput);
int aws_cryptosdk_priv_check_trailer(
    struct aws_cryptosdk_session *AWS_RESTRICT session, struct aws_byte_cursor *AWS_RESTRICT pinput);

/* Encrypt path */
void aws_cryptosdk_priv_encrypt_compute_body_estimate(struct aws_cryptosdk_session *session);

int aws_cryptosdk_priv_try_gen_key(struct aws_cryptosdk_session *session);
int aws_cryptosdk_priv_try_write_header(struct aws_cryptosdk_session *session, struct aws_byte_buf *output);
int aws_cryptosdk_priv_try_encrypt_body(
    struct aws_cryptosdk_session *AWS_RESTRICT session,
    struct aws_byte_buf *AWS_RESTRICT poutput,
    struct aws_byte_cursor *AWS_RESTRICT pinput);
int aws_cryptosdk_priv_write_trailer(
    struct aws_cryptosdk_session *AWS_RESTRICT session, struct aws_byte_buf *AWS_RESTRICT poutput);

#endif
