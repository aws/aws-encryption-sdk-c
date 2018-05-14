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

#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/cipher.h>

enum session_mode {
    MODE_UNINIT = 0,
    MODE_ENCRYPT,
    MODE_DECRYPT
};

enum session_state {
/* State ST_CONFIG: Initial configuration. No data has been supplied */
    ST_CONFIG = 0,
/* State ST_ERROR: De/encryption failure. No data will be processed until reset */
    ST_ERROR,
/* State ST_HEADER:
 *   On decrypt: Some data has been provided, but the header is still incomplete.
 *   On encrypt: Some of the header has been generated, but we haven't written the whole thing
 */
    ST_HEADER,
/* State ST_KEYING:
 *   We are prepared to invoke the CMM to obtain cryptographic materials.
 *   If a failure occurs here, we remain in ST_KEYING and can retry.
 *   XXX: Should we make this a terminal state?
 */
    ST_KEYING,
/* State ST_BODY:
 * Normal body data processing. We will consume (or generate) entire frames of data at a time.
 * In the case of a single-frame message, we will not consume any data until the message length
 * is set
 */
    ST_BODY,
/* State ST_TRAILER:
 * Framed mode only. We're waiting to consume or generate the final trailer
 */
    ST_TRAILER,
/* State ST_DONE: Encryption or decryption complete. */
    ST_DONE
};

struct aws_cryptosdk_session {
    struct aws_allocator *alloc;
    int error;
    enum session_mode mode;
    enum session_state state;

    /* The actual header, if parsed */
    uint8_t *header_copy;
    size_t header_size;
    struct aws_cryptosdk_hdr header;

    /* Estimate for the amount of input data needed to make progress. */
    size_t input_size_estimate;

    /* Estimate for the amount of output buffer needed to make progress. */
    size_t output_size_estimate;

    uint64_t frame_seqno;

    const struct aws_cryptosdk_alg_properties *alg_props;

    /* Decrypted, derived (if applicable) content key */
    struct content_key content_key;
};


#endif
