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

struct aws_cryptosdk_all_struct {
    struct aws_cryptosdk_session *session;
    struct aws_cryptosdk_cmm *cmm;
    struct aws_cryptosdk_mkp *mkp;
};

struct aws_cryptosdk_all_struct aws_cryptosdk_all_init(enum aws_cryptosdk_mode mode, struct aws_cryptosdk_keyring *mk) {
    struct aws_cryptosdk_all_struct result;

    result.cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), mk);
    if (!result.cmm) abort();

    result.session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), mode, result.cmm);
    if (!result.session) abort();

    return result;
}

void aws_cryptosdk_destroy(struct aws_cryptosdk_all_struct result) {
    aws_cryptosdk_session_destroy(result.session);
    aws_cryptosdk_cmm_destroy(result.cmm);
}

int aws_cryptosdk_process(struct aws_cryptosdk_keyring *mk,
                          enum aws_cryptosdk_mode mode,
                          const struct aws_byte_buf *in,
                          struct aws_byte_buf *out) {

    struct aws_cryptosdk_all_struct aws_crypto_sdk = aws_cryptosdk_all_init(mode, mk);


    aws_cryptosdk_session_set_message_size(aws_crypto_sdk.session, in->len);

    size_t in_consumed, out_consumed;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(aws_crypto_sdk.session,
                                                      out->buffer, out->len, &out_consumed,
                                                      in->buffer, in->len, &in_consumed
    ));

    TEST_ASSERT_INT_EQ(in_consumed, in->len);
    TEST_ASSERT(aws_cryptosdk_session_is_done(aws_crypto_sdk.session));

    aws_cryptosdk_destroy(aws_crypto_sdk);

    out->len = out_consumed;
    return 0;
}

#endif //AWS_ENCRYPTION_SDK_TEST_CRYPTO_H
