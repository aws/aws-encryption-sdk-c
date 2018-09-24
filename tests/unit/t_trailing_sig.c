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

#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/default_cmm.h>
#include <stdlib.h>
#include "testing.h"
#include "testutil.h"
#include "zero_keyring.h"
#include "counting_keyring.h"

AWS_STATIC_STRING_FROM_LITERAL(EC_PUBLIC_KEY_FIELD, "aws-crypto-public-key");

struct strip_key_cmm {
    const struct aws_cryptosdk_cmm_vt *vt;
    struct aws_cryptosdk_cmm *cmm;
};

static void strip_key_destroy(struct aws_cryptosdk_cmm *cmm) {
    // no-op
}

static int strip_key_gen_mat(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_encryption_materials **output,
    struct aws_cryptosdk_encryption_request *request
) {
    struct strip_key_cmm *self = (struct strip_key_cmm *)cmm;
    int rv = aws_cryptosdk_cmm_generate_encryption_materials(self->cmm, output, request);

    if (rv == 0) {
        aws_hash_table_remove(request->enc_context, EC_PUBLIC_KEY_FIELD, NULL, NULL);
    }

    return rv;
}

static const struct aws_cryptosdk_cmm_vt strip_key_cmm_vt = {
    .vt_size = sizeof(strip_key_cmm_vt),
    .name = "strip_key_cmm",
    .destroy = strip_key_destroy,
    .generate_encryption_materials = strip_key_gen_mat,
    .decrypt_materials = NULL
};

static int trailing_sig_no_key() {
    struct aws_byte_buf buf = {0};
    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), aws_cryptosdk_zero_keyring_new());
    TEST_ASSERT_ADDR_NOT_NULL(cmm);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384));

    TEST_ASSERT_SUCCESS(aws_byte_buf_init(aws_default_allocator(), &buf, 1024));

    struct strip_key_cmm strip_key_cmm_s = {.vt = &strip_key_cmm_vt, .cmm = cmm};
    struct aws_cryptosdk_cmm *enc_cmm = (struct aws_cryptosdk_cmm *)&strip_key_cmm_s;

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, enc_cmm);
    TEST_ASSERT_ADDR_NOT_NULL(session);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, 1));

    size_t ignored;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session, buf.buffer, buf.capacity, &buf.len, (const uint8_t *)"x", 1, &ignored));
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    aws_cryptosdk_session_destroy(session);

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, cmm);
    TEST_ASSERT_ADDR_NOT_NULL(session);

    uint8_t outbuf[256];
    size_t ignored2;
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT,
        aws_cryptosdk_session_process(session, outbuf, sizeof(outbuf), &ignored, buf.buffer, buf.len, &ignored2)
    );

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_cmm_release(cmm);
    aws_byte_buf_clean_up(&buf);

    return 0;
}

static int trailing_sig_no_sig() {
    struct aws_byte_buf buf = {0};
    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), aws_cryptosdk_zero_keyring_new());
    TEST_ASSERT_ADDR_NOT_NULL(cmm);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384));
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(aws_default_allocator(), &buf, 1024));

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    TEST_ASSERT_ADDR_NOT_NULL(session);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, 1));

    size_t ignored;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session, buf.buffer, buf.capacity, &buf.len, (const uint8_t *)"x", 1, &ignored));
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    aws_cryptosdk_session_destroy(session);

    // Strip off the trailing signature; we know that it has a size of two bytes plus the hard-coded
    // signature length.
    buf.len -= aws_cryptosdk_alg_props(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384)->signature_len + 2;

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, cmm);
    TEST_ASSERT_ADDR_NOT_NULL(session);

    uint8_t outbuf[256];
    size_t ignored2;
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_process(session, outbuf, sizeof(outbuf), &ignored, buf.buffer, buf.len, &ignored2)
    );
    // Message should be incomplete
    TEST_ASSERT(!aws_cryptosdk_session_is_done(session));

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_cmm_release(cmm);
    aws_byte_buf_clean_up(&buf);

    return 0;
}

static int trailing_sig_bad_sig() {
    struct aws_byte_buf buf = {0};
    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), aws_cryptosdk_zero_keyring_new());
    TEST_ASSERT_ADDR_NOT_NULL(cmm);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384));
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(aws_default_allocator(), &buf, 1024));

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    TEST_ASSERT_ADDR_NOT_NULL(session);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, 1));

    size_t ignored;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session, buf.buffer, buf.capacity, &buf.len, (const uint8_t *)"x", 1, &ignored));
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    aws_cryptosdk_session_destroy(session);

    // Corrupt the signature
    buf.buffer[buf.len - 1]++;

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, cmm);
    TEST_ASSERT_ADDR_NOT_NULL(session);

    uint8_t outbuf[256];
    size_t ignored2;
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT,
        aws_cryptosdk_session_process(session, outbuf, sizeof(outbuf), &ignored, buf.buffer, buf.len, &ignored2)
    );
    // Message should be incomplete
    TEST_ASSERT(!aws_cryptosdk_session_is_done(session));

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_cmm_release(cmm);
    aws_byte_buf_clean_up(&buf);

    return 0;
}

struct test_case trailing_sig_test_cases[] = {
    { "trailing_sig", "no_key", trailing_sig_no_key },
    { "trailing_sig", "no_sig", trailing_sig_no_sig },
    { "trailing_sig", "bad_sig", trailing_sig_bad_sig },
    { NULL }
};
