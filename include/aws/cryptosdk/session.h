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

#ifndef AWS_CRYPTOSDK_SESSION_H
#define AWS_CRYPTOSDK_SESSION_H

#include <stdbool.h>

#include <aws/common/common.h>
#include <aws/cryptosdk/header.h>

struct aws_cryptosdk_session;

struct aws_cryptosdk_session *aws_cryptosdk_session_new(
    struct aws_allocator *allocator
);

void aws_cryptosdk_session_destroy(struct aws_cryptosdk_session *session);

/**
 * Prepares the session to start a new decryption operation.
 * The session will retain any configured crypto material manager,
 * master key provider, or master key, as well as its associated
 * allocator. All other state will be reset to prepare for processing
 * a new message.
 *
 * This method can be used to reset a session currently in an error
 * state as well.
 */
int aws_cryptosdk_session_init_decrypt(
    struct aws_cryptosdk_session *session
);

#if 0
// TODO: CMMs will be implemented later. For now we assume an all-zero
// data key.

int aws_cryptosdk_session_set_cmm(
    struct aws_cryptosdk_session *session,
    struct aws_cryptosdk_cmm *cmm
);

// MKP variant...
// MK variant...
#endif

#if 0
/**
 * Retrieves a reference to the header associated with a session.
 * This function will fail with an AWS_CRYPTOSDK_ERR_BAD_STATE error
 * if the header is not yet available. This will happen if, for encrypt,
 * process has not yet been called, or if on decrypt not enough data has
 * been supplied to deserialize the header.
 *
 * The header returned is owned by the session and must not be modified.
 * It will be destroyed when the session is reinitialized or destroyed.
 */
int aws_cryptosdk_session_get_header(
    const struct aws_cryptosdk_session *session,
    const struct aws_cryptosdk_header **header
);
#endif

/**
 * Attempts to process some data through the cryptosdk session.
 * This method may do any combination of
 *   1. Consuming some data from the input buffer
 *   2. Producing some data in the output buffer
 *   3. Entering an error state, and raising the error in question.
 *
 * The data referenced by the input and output cursors must not overlap.
 * If this method raises an error, the contents of the output buffer will
 * be zeroed. The buffer referenced by the input buffer will never be modified.
 *
 * If there is insufficient output space and/or insufficient input
 * data, this method may not make any progress. The aws_cryptosdk_session_estimate_buf
 * method may be used to determine how much data may be needed at
 * this stage of processing. Note that these estimates may change once
 * the header has been parsed.
 *
 * Upon return, *out_bytes_written and *in_bytes_read will report the number
 * of bytes consumed from the output and input buffers, respectively.
 *
 * This method will return successfully unless the session has entered
 * an error state. Use aws_cryptosdk_session_is_done to determine if the
 * entire message has been processed.
 */
int aws_cryptosdk_session_process(
    struct aws_cryptosdk_session *session,
    uint8_t *outp, size_t outlen, size_t *out_bytes_written,
    const uint8_t *inp, size_t inlen, size_t *in_bytes_read
);

/**
 * Returns true if the session has finished processing the entire message.
 */
bool aws_cryptosdk_session_is_done(const struct aws_cryptosdk_session *session);

/**
 * Estimates the amount of buffer space needed to make forward progress.
 * Supplying the amount of data indicated here to _process guarantees that
 * some kind of progress will be made (if only to enter an error state).
 * Note that these values will change after initial header (de)serialization
 * is completed.
 *
 * This method never fails, but if the session is in an error state or is 
 * only partially initialized, the returned sizes will be 1.
 */
void aws_cryptosdk_session_estimate_buf(
    const struct aws_cryptosdk_session *session,
    size_t * restrict outbuf_needed,
    size_t * restrict inbuf_needed
);

#endif
