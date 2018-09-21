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

static uint8_t *pt_buf;
static size_t pt_size, pt_offset;
static uint8_t *ct_buf;
static size_t ct_buf_size, ct_size;
static struct aws_cryptosdk_session *session;
static struct aws_cryptosdk_cmm *cmm = NULL;
static int precise_size_set = 0;

static int create_session(enum aws_cryptosdk_mode mode, struct aws_cryptosdk_keyring *kr) {
    if (session) aws_cryptosdk_session_destroy(session);
    if (cmm) aws_cryptosdk_cmm_destroy(cmm);

    session = NULL;
    cmm = NULL;

    cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);
    if (!cmm) abort();

    session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), mode, cmm);
    if (!session) abort();

    return AWS_OP_SUCCESS;
}

static void init_bufs(size_t pt_len) {
    pt_buf = aws_mem_acquire(aws_default_allocator(), pt_len);
    pt_size = pt_len;
    aws_cryptosdk_genrandom(pt_buf, pt_size);

    ct_buf_size = 1024;
    ct_buf = aws_mem_acquire(aws_default_allocator(), ct_buf_size);
    ct_size = 0;

    precise_size_set = 0;
    pt_offset = 0;
}

static void free_bufs() {
    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_cmm_destroy(cmm);
    cmm = NULL;
    session = NULL;

    aws_mem_release(aws_default_allocator(), pt_buf);
    aws_mem_release(aws_default_allocator(), ct_buf);
    pt_size = ct_buf_size = ct_size = 0;
    pt_buf = ct_buf = NULL;
}

static void grow_buf(uint8_t **bufpp, size_t *cur_size, size_t needed) {
    if (*cur_size >= needed) {
        return;
    }

    size_t new_size = *cur_size;
    while (new_size < needed) {
        new_size *= 2;
        if (new_size < *cur_size) {
            fprintf(stderr, "Maximum buffer size exceeded\n");
            abort();
        }
    }

    // aws_mem_realloc wants a void **
    void *tmpp = *bufpp;
    if (aws_mem_realloc(aws_default_allocator(), &tmpp, *cur_size, new_size)) {
        fprintf(stderr, "Out of memory\n");
        abort();
    }
    *bufpp = tmpp;

    *cur_size = new_size;
}

static int pump_ciphertext(size_t ct_window, size_t *ct_consumed, size_t pt_window, size_t *pt_consumed) {
    grow_buf(&ct_buf, &ct_buf_size, ct_size + ct_window);

    if (pt_window + pt_offset > pt_size) {
        pt_window = pt_size - pt_offset;
    }

    *ct_consumed = *pt_consumed = 0;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(
        session,
        ct_buf + ct_size, ct_window, ct_consumed,
        pt_buf + pt_offset, pt_window, pt_consumed
    ));

    ct_size += *ct_consumed;
    pt_offset += *pt_consumed;

    if (precise_size_set && !*ct_consumed) {
        // We made no progress. Make sure output/input estimates are greater than the amount of data
        // we supplied - or that we're completely done
        size_t out_needed, in_needed;

        aws_cryptosdk_session_estimate_buf(session, &out_needed, &in_needed);

        TEST_ASSERT(aws_cryptosdk_session_is_done(session)
            || out_needed > ct_window
            || in_needed > pt_window
        );
    }

    return 0;
}

static int check_ciphertext() {
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT));

    uint8_t *pt_check_buf = aws_mem_acquire(aws_default_allocator(), pt_size);
    if (!pt_check_buf) {
        fprintf(stderr, "Out of memory\n");
        abort();
    }
    memset(pt_check_buf, 0, pt_size);

    size_t out_written, in_read;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session,
        pt_check_buf, pt_size, &out_written,
        ct_buf, ct_size, &in_read
    ));

    TEST_ASSERT_INT_EQ(out_written, pt_size);
    TEST_ASSERT_INT_EQ(in_read, ct_size);
    TEST_ASSERT_INT_EQ(0, memcmp(pt_check_buf, pt_buf, pt_size));
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    aws_mem_release(aws_default_allocator(), pt_check_buf);

    return 0;
}

static int probe_buffer_size_estimates() {
    /*
     * This method feeds pump_ciphertext increasingly larger buffers
     * until something happens. By doing so we can verify that estimates work
     * properly (i.e. when we pass exactly the estimate, either the estimate
     * must be updated or some data must be consumed).
     */

    size_t pt_limit = 1, ct_limit = 1;
    size_t pt_est, ct_est;
    size_t pt_consumed = 0, ct_consumed = 0;

    while (true) {
        if (pump_ciphertext(ct_limit, &ct_consumed, pt_limit, &pt_consumed)) return 1;

        aws_cryptosdk_session_estimate_buf(session, &ct_est, &pt_est);

        if (pt_consumed || ct_consumed) {
            break;
        } else if (pt_limit < pt_est && pt_limit <= pt_size - pt_offset) {
            pt_limit++;
        } else if (ct_limit < ct_est) {
            pt_limit = 1;
            ct_limit++;
        } else if (pt_limit <= pt_est && pt_limit <= pt_size - pt_offset) {
            // Up to this point we don't go any further than (pt_est - 1, ct_est), so once we
            // hit the ct estimate we need to increment the plaintext all the way up to the estimated
            // size.
            pt_limit++;
        } else {
            TEST_ASSERT(!precise_size_set);
            return 0;
        }
    }

    return 0;
}

static int test_small_buffers() {
    init_bufs(31);
    create_session(AWS_CRYPTOSDK_ENCRYPT, aws_cryptosdk_zero_keyring_new());
    aws_cryptosdk_session_set_frame_size(session, 16);

    if (probe_buffer_size_estimates()) return 1; // should emit header
    if (probe_buffer_size_estimates()) return 1; // should emit frame 1
    if (probe_buffer_size_estimates()) return 1; // should not emit anything
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, pt_size));
    precise_size_set = true;
    if (probe_buffer_size_estimates()) return 1; // should emit final frame
    if (probe_buffer_size_estimates()) return 1; // should emit trailer

    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    if (check_ciphertext()) return 1;

    free_bufs();

    return 0;
}

int test_simple_roundtrip() {
    init_bufs(1024);

    size_t ct_consumed, pt_consumed;
    create_session(AWS_CRYPTOSDK_ENCRYPT, aws_cryptosdk_zero_keyring_new());
    aws_cryptosdk_session_set_message_size(session, pt_size);
    precise_size_set = true;

    if (pump_ciphertext(2048, &ct_consumed, pt_size, &pt_consumed)) return 1;
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    if (check_ciphertext()) return 1;

    free_bufs();

    return 0;
}

int test_different_keyring_cant_decrypt() {
    init_bufs(1 /*1024*/);

    size_t ct_consumed, pt_consumed;
    create_session(AWS_CRYPTOSDK_ENCRYPT, aws_cryptosdk_counting_keyring());
    aws_cryptosdk_session_set_message_size(session, pt_size);
    precise_size_set = true;

    if (pump_ciphertext(2048, &ct_consumed, pt_size, &pt_consumed)) return 1;
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    create_session(AWS_CRYPTOSDK_DECRYPT, aws_cryptosdk_zero_keyring_new());
    hexdump(stderr, ct_buf, ct_size);

#if 0
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_NO_MASTER_KEYS_FOUND,
        aws_cryptosdk_session_process(session,
            pt_buf, pt_size, &pt_consumed,
            ct_buf, ct_size, &ct_consumed
        )
    );
#else
    // We don't yet return the correct error, but we can check that -some- error is returned.
    TEST_ASSERT_INT_EQ(AWS_OP_ERR,
        aws_cryptosdk_session_process(session,
            pt_buf, pt_size, &pt_consumed,
            ct_buf, ct_size, &ct_consumed
        )
    );
#endif

    free_bufs();

    return 0;
}


int test_changed_keyring_can_decrypt() {
    init_bufs(1 /*1024*/);

    size_t ct_consumed, pt_consumed;
    create_session(AWS_CRYPTOSDK_ENCRYPT, aws_cryptosdk_counting_keyring());
    aws_cryptosdk_session_set_message_size(session, pt_size);
    precise_size_set = true;

    if (pump_ciphertext(2048, &ct_consumed, pt_size, &pt_consumed)) return 1;
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    if (check_ciphertext()) return 1;

    free_bufs();

    return 0;
}

static int test_algorithm_override_once(enum aws_cryptosdk_alg_id alg_id) {
    init_bufs(1);

    size_t ct_consumed, pt_consumed;
    enum aws_cryptosdk_alg_id reported_alg_id;
    create_session(AWS_CRYPTOSDK_ENCRYPT, aws_cryptosdk_counting_keyring());
    aws_cryptosdk_default_cmm_set_alg_id(cmm, alg_id);
    aws_cryptosdk_session_set_message_size(session, pt_size);
    precise_size_set = true;

    if (pump_ciphertext(2048, &ct_consumed, pt_size, &pt_consumed)) return 1;
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_get_algorithm(session, &reported_alg_id));
    TEST_ASSERT_INT_EQ(alg_id, reported_alg_id);

    if (check_ciphertext()) return 1;

    // Session is now configured for decrypt and should report decryption-side ID
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_get_algorithm(session, &reported_alg_id));
    TEST_ASSERT_INT_EQ(alg_id, reported_alg_id);

    free_bufs();

    return 0;
}

int test_algorithm_override() {
    return test_algorithm_override_once(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE)
        || test_algorithm_override_once(AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE)
        || test_algorithm_override_once(AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE)
        || test_algorithm_override_once(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256)
        || test_algorithm_override_once(AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384)
        || test_algorithm_override_once(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384)
        || test_algorithm_override_once(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE)
        || test_algorithm_override_once(AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE)
        || test_algorithm_override_once(AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE);
}

struct test_case encrypt_test_cases[] = {
    { "encrypt", "test_simple_roundtrip", test_simple_roundtrip },
    { "encrypt", "test_small_buffers", test_small_buffers },
    { "encrypt", "test_different_keyring_cant_decrypt", &test_different_keyring_cant_decrypt },
    { "encrypt", "test_changed_keyring_can_decrypt", &test_changed_keyring_can_decrypt },
    { "encrypt", "test_algorithm_override", &test_algorithm_override },
    { NULL }
};
