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

#ifndef AWS_ENCRYPTION_SDK_TEST_CRYPTO_H
#define AWS_ENCRYPTION_SDK_TEST_CRYPTO_H

#include <stdlib.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/default_cmm.h>
#include "testing.h"

struct t_aws_cryptosdk_session_cmm_struct {
    struct aws_cryptosdk_session *session;
    struct aws_cryptosdk_cmm *cmm;
};

/**
 * Initializes aws_cryptoskd cmm and session
 */
struct t_aws_cryptosdk_session_cmm_struct t_aws_cryptosdk_all_init(enum aws_cryptosdk_mode mode,
                                                                   struct aws_cryptosdk_keyring *mk) {
    struct t_aws_cryptosdk_session_cmm_struct result;

    result.cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), mk);
    if (!result.cmm) abort();

    result.session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), mode, result.cmm);
    if (!result.session) abort();

    return result;
}

/**
 * Destroys aws_cryptoskd cmm and session
 */
void t_aws_cryptosdk_destroy(struct t_aws_cryptosdk_session_cmm_struct result) {
    aws_cryptosdk_session_destroy(result.session);
    aws_cryptosdk_cmm_destroy(result.cmm);
}

/**
 * Generates key or decrypts a payload
 * @param keyring Keyring
 * @param mode Encrypt/Decrypt
 * @param in Bytes in
 * @param out Bytes out
 * @param expected_process_status aws_cryptosdk_session_process expected status
 * @return 0 on success
 */
int t_aws_cryptosdk_process(struct aws_cryptosdk_keyring *keyring,
                            enum aws_cryptosdk_mode mode,
                            const struct aws_byte_buf *in,
                            struct aws_byte_buf *out,
                            int expected_process_status = AWS_OP_SUCCESS) {
    struct t_aws_cryptosdk_session_cmm_struct aws_crypto_sdk = t_aws_cryptosdk_all_init(mode, keyring);

    aws_cryptosdk_session_set_message_size(aws_crypto_sdk.session, in->len);

    size_t in_consumed, out_consumed;
    TEST_ASSERT(aws_cryptosdk_session_process(aws_crypto_sdk.session,
                                              out->buffer, out->len, &out_consumed,
                                              in->buffer, in->len, &in_consumed) == expected_process_status);

    if (expected_process_status != AWS_OP_ERR) {
        TEST_ASSERT_INT_EQ(in_consumed, in->len);
        TEST_ASSERT(aws_cryptosdk_session_is_done(aws_crypto_sdk.session));
    }

    t_aws_cryptosdk_destroy(aws_crypto_sdk);

    out->len = out_consumed;
    return 0;
}

#endif //AWS_ENCRYPTION_SDK_TEST_CRYPTO_H
