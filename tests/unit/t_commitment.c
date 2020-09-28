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

#include <aws/common/common.h>
#include <aws/common/encoding.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>
#include <stdlib.h>
#include "counting_keyring.h"
#include "testing.h"
#include "testutil.h"
#include "zero_keyring.h"

struct stub_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_allocator *alloc;

    struct aws_byte_buf data_key;
};

static void stub_keyring_destroy(struct aws_cryptosdk_keyring *kr) {
    struct stub_keyring *stub = (struct stub_keyring *)kr;

    aws_byte_buf_clean_up(&stub->data_key);
    aws_mem_release(stub->alloc, stub);
}

AWS_STATIC_STRING_FROM_LITERAL(static_stub_str, "stub");

static int stub_keyring_decrypt(
    struct aws_cryptosdk_keyring *kr,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    const struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    struct stub_keyring *stub = (struct stub_keyring *)kr;

    struct aws_byte_cursor c = aws_byte_cursor_from_buf(&stub->data_key);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy(unencrypted_data_key, request_alloc, &stub->data_key)) {
        return AWS_OP_ERR;
    }

    aws_cryptosdk_keyring_trace_add_record(
        request_alloc, keyring_trace, static_stub_str, static_stub_str, AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY);

    return AWS_OP_SUCCESS;
}

const static struct aws_cryptosdk_keyring_vt stub_keyring_vt = { .vt_size    = sizeof(stub_keyring_vt),
                                                                 .name       = "stub keyring",
                                                                 .destroy    = stub_keyring_destroy,
                                                                 .on_decrypt = stub_keyring_decrypt,
                                                                 .on_encrypt = NULL };

static struct aws_cryptosdk_keyring *stub_keyring_new(struct aws_allocator *alloc, const char *data_key_b64) {
    struct stub_keyring *kr = aws_mem_acquire(alloc, sizeof(*kr));
    if (!kr) {
        return NULL;
    }

    kr->alloc    = alloc;
    kr->data_key = easy_b64_decode(data_key_b64);

    aws_cryptosdk_keyring_base_init(&kr->base, &stub_keyring_vt);

    return &kr->base;
}

struct commitment_kat_case {
    const char *ciphertext_b64;
    const char *datakey_b64;
    const char *comment;
    bool should_succeed;
};

static const struct commitment_kat_case TEST_CASES[] = {
// This file has an export of the same vectors used by the commitment_known_answer
// C++ integration test, but with the relevant data extracted so we can partially
// run the test in a pure-C environment, or one with no network access.
#include "t_commitment_vectors.inc"
    { 0 }
};

static int test_one(const struct commitment_kat_case *t) {
    struct aws_byte_buf ciphertext   = easy_b64_decode(t->ciphertext_b64);
    struct aws_cryptosdk_keyring *kr = stub_keyring_new(aws_default_allocator(), t->datakey_b64);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);
    TEST_ASSERT_ADDR_NOT_NULL(cmm);

    struct aws_byte_buf plaintext;
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(&plaintext, aws_default_allocator(), ciphertext.len));

    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, cmm);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);

    size_t consumed, produced;
    int rv = aws_cryptosdk_session_process(
        session, plaintext.buffer, plaintext.capacity, &produced, ciphertext.buffer, ciphertext.len, &consumed);

    if (t->should_succeed) {
        TEST_ASSERT_SUCCESS(rv);
        TEST_ASSERT(aws_cryptosdk_session_is_done(session));
    } else {
        TEST_ASSERT_INT_NE(AWS_OP_SUCCESS, rv);
    }

    aws_cryptosdk_session_destroy(session);
    aws_byte_buf_clean_up(&plaintext);
    aws_byte_buf_clean_up(&ciphertext);

    return 0;
}

static int test_known_answers() {
    int failed = 0;
    for (int i = 0; TEST_CASES[i].ciphertext_b64; i++) {
        if (TEST_CASES[i].datakey_b64[0] == '\0') {
            fprintf(stderr, "[ SKIP ] %s\n", TEST_CASES[i].comment);
            continue;
        }

        int rv = test_one(&TEST_CASES[i]);
        if (rv) {
            fprintf(stderr, "[FAILED] %s\n", TEST_CASES[i].comment);
            failed = 1;
        } else {
            fprintf(stderr, "[  OK  ] %s\n", TEST_CASES[i].comment);
        }
    }

    return failed;
}

static const char *identify_policy(enum aws_cryptosdk_commitment_policy policy) {
    switch (policy) {
        case 0: return "UNSET";
        case COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT: return "COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT";
        case COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT: return "COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT";
        case COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
            return "COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT";
        default: return "UNKNOWN";
    }
}

static int test_commitment_policy_with_sessions(
    struct aws_cryptosdk_session *enc,
    struct aws_cryptosdk_session *dec,
    uint32_t enc_policy,
    uint32_t dec_policy,
    bool should_succeed) {
    if (enc_policy) TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_commitment_policy(enc, enc_policy));
    if (dec_policy) TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_commitment_policy(dec, dec_policy));

    uint8_t ciphertext_buf[1024], pt_buf[16];
    size_t ct_len, pt_advanced, ct_consumed;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(enc, 0));
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_process(enc, ciphertext_buf, sizeof(ciphertext_buf), &ct_len, "", 0, &pt_advanced));
    TEST_ASSERT(aws_cryptosdk_session_is_done(enc));

    if (should_succeed) {
        TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(
            dec, pt_buf, sizeof(pt_buf), &pt_advanced, ciphertext_buf, ct_len, &ct_consumed));
        TEST_ASSERT(aws_cryptosdk_session_is_done(dec));
    } else {
        TEST_ASSERT_ERROR(
            AWS_CRYPTOSDK_ERR_COMMITMENT_POLICY_VIOLATION,
            aws_cryptosdk_session_process(
                dec, pt_buf, sizeof(pt_buf), &pt_advanced, ciphertext_buf, ct_len, &ct_consumed));
    }

    return 0;
}

static int test_commitment_policy(uint32_t enc_policy, uint32_t dec_policy, bool should_succeed) {
    struct aws_cryptosdk_session *enc;
    struct aws_cryptosdk_session *dec;
    struct aws_cryptosdk_keyring *kr;
    struct aws_cryptosdk_cmm *cmm;

    kr  = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    enc = aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);
    dec = aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, kr);
    if (test_commitment_policy_with_sessions(enc, dec, enc_policy, dec_policy, should_succeed)) {
        fprintf(
            stderr,
            "[FAILED] test_commitment_policy using aws_cryptosdk_session_new_from_keyring_2; enc policy=%s dec "
            "policy=%s\n",
            identify_policy(enc_policy),
            identify_policy(dec_policy));
        return 1;
    }
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_session_destroy(enc);
    aws_cryptosdk_session_destroy(dec);

    kr  = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);
    enc = aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    dec = aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, cmm);
    if (test_commitment_policy_with_sessions(enc, dec, enc_policy, dec_policy, should_succeed)) {
        fprintf(
            stderr,
            "[FAILED] test_commitment_policy using aws_cryptosdk_session_new_from_cmm_2; enc policy=%s dec policy=%s\n",
            identify_policy(enc_policy),
            identify_policy(dec_policy));
        return 1;
    }
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_session_destroy(enc);
    aws_cryptosdk_session_destroy(dec);

    return 0;
}

static int commitment_test_matrix() {
    int failed = 0;

    failed |= test_commitment_policy(
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,  // encrypt
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,  // decrypt
        true);
    failed |= test_commitment_policy(
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,   // encrypt
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,  // decrypt
        true);
    failed |= test_commitment_policy(
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,     // encrypt
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // decrypt
        false);

    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,  // encrypt
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,   // decrypt
        true);
    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,  // encrypt
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,  // decrypt
        true);
    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,    // encrypt
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // decrypt
        true);

    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // encrypt
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,     // decrypt
        true);
    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // encrypt
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,    // decrypt
        true);
    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // encrypt
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // decrypt
        true);

    failed |= test_commitment_policy(
        0,  // encrypt (default)
        0,  // decrypt (default)
        true);

    failed |= test_commitment_policy(
        0,                                               // encrypt (default)
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,  // decrypt
        true);

    failed |= test_commitment_policy(
        0,                                                // encrypt (default)
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,  // decrypt
        true);

    failed |= test_commitment_policy(
        0,                                                  // encrypt (default)
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // decrypt
        true);

    failed |= test_commitment_policy(
        COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,  // encrypt
        0,                                               // decrypt
        false);

    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,  // encrypt
        0,                                                // decrypt
        true);

    failed |= test_commitment_policy(
        COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,  // encrypt
        0,                                                  // decrypt
        true);

    return failed;
}

static int attempt_encrypt(
    int expected_result, struct aws_cryptosdk_cmm *cmm, enum aws_cryptosdk_commitment_policy policy) {
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    if (policy) TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_commitment_policy(session, policy));

    uint8_t ct_buf[1024], pt_buf[1] = { 0 };
    size_t pt_consumed, ct_produced;

    if (expected_result) {
        TEST_ASSERT_ERROR(
            expected_result,
            aws_cryptosdk_session_process(
                session, ct_buf, sizeof(ct_buf), &ct_produced, pt_buf, sizeof(pt_buf), &pt_consumed));
    } else {
        TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(
            session, ct_buf, sizeof(ct_buf), &ct_produced, pt_buf, sizeof(pt_buf), &pt_consumed));
    }

    aws_cryptosdk_session_destroy(session);

    return 0;
}

static int alg_id_compatible() {
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_cmm *cmm    = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);

    // Non-committing algorithm, forbid-committing policy
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256));
    if (attempt_encrypt(AWS_OP_SUCCESS, cmm, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT)) return 1;

    // Committing algorithm, default policy
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY));
    if (attempt_encrypt(AWS_OP_SUCCESS, cmm, (enum aws_cryptosdk_commitment_policy)0)) return 1;

    // Committing algorithm, allow-committing policy
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY));
    if (attempt_encrypt(AWS_OP_SUCCESS, cmm, COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT)) return 1;

    // Committing algorithm, require-committing policy
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY));
    if (attempt_encrypt(AWS_OP_SUCCESS, cmm, COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT)) return 1;

    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

static int alg_id_conflict() {
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_cmm *cmm    = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);

    // Committing algorithm, non-committing policy
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY));
    if (attempt_encrypt(
            AWS_CRYPTOSDK_ERR_COMMITMENT_POLICY_VIOLATION, cmm, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT))
        return 1;

    // Non-committing algorithm, default policy (require committing)
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256));
    if (attempt_encrypt(AWS_CRYPTOSDK_ERR_COMMITMENT_POLICY_VIOLATION, cmm, (enum aws_cryptosdk_commitment_policy)0))
        return 1;

    // Non-committing algorithm, allow-committing policy
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256));
    if (attempt_encrypt(
            AWS_CRYPTOSDK_ERR_COMMITMENT_POLICY_VIOLATION, cmm, COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT))
        return 1;

    // Non-committing algorithm, require-committing policy
    TEST_ASSERT_SUCCESS(aws_cryptosdk_default_cmm_set_alg_id(cmm, ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256));
    if (attempt_encrypt(
            AWS_CRYPTOSDK_ERR_COMMITMENT_POLICY_VIOLATION, cmm, COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT))
        return 1;

    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

static int valid_policy() {
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT));
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT));

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

static int invalid_policy() {
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);

    TEST_ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_cryptosdk_session_set_commitment_policy(session, 0x42424242));

    /* Session should be broken */
    uint8_t ct_buf[1024], pt_buf[1] = { 0 };
    size_t pt_consumed, ct_produced;

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_process(
            session, ct_buf, sizeof(ct_buf), &ct_produced, pt_buf, sizeof(pt_buf), &pt_consumed));

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

static int change_policy() {
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));

    /* Session should be broken */
    uint8_t ct_buf[1024], pt_buf[1] = { 0 };
    size_t pt_consumed, ct_produced;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(
        session, ct_buf, sizeof(ct_buf), &ct_produced, pt_buf, sizeof(pt_buf), &pt_consumed));

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));

    ct_produced = 0x42424242;

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_process(
            session, ct_buf, sizeof(ct_buf), &ct_produced, pt_buf, sizeof(pt_buf), &pt_consumed));
    TEST_ASSERT_INT_EQ(ct_produced, 0);

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

static int default_session_policy() {
    struct aws_cryptosdk_session *session;
    struct aws_cryptosdk_keyring *kr;
    struct aws_cryptosdk_cmm *cmm;

    kr      = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    session = aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);
    TEST_ASSERT(COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT == session->commitment_policy);
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_session_destroy(session);

    kr      = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    cmm     = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);
    session = aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    TEST_ASSERT(COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT == session->commitment_policy);
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_session_destroy(session);

    return 0;
}

struct test_case commitment_test_cases[] = { { "commitment", "known_answer", test_known_answers },
                                             { "commitment", "test_matrix", commitment_test_matrix },
                                             { "commitment", "alg_id_compatible", alg_id_compatible },
                                             { "commitment", "alg_id_conflict", alg_id_conflict },
                                             { "commitment", "valid_policy", valid_policy },
                                             { "commitment", "invalid_policy", invalid_policy },
                                             { "commitment", "change_policy_partway_through", change_policy },
                                             { "commitment", "default_session_policy", default_session_policy },
                                             { NULL } };
