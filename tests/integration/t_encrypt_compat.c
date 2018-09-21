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

#include "testing.h"
#include "testutil.h"
#include "zero_keyring.h"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/default_cmm.h>

#include <curl/curl.h>

static enum aws_cryptosdk_alg_id known_algorithms[] = {
    AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
    AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
    AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256,
    AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
    AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
    AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE,
    AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE,
    AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE,
    AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE
};

static enum aws_cryptosdk_alg_id alg_to_use;

// This endpoint attempts to decrypt a ciphertext encrypted with an all-zero
// data key (or with one of our public resource CMKs).

// The ciphertext is passed as the body of a POST; on success, a 200 is returned
// along with the plaintext. On failure, a 400 is returned with a java stacktrace
// in the body.

static const char *apigw_url = "https://yrniiep3a0.execute-api.us-west-2.amazonaws.com/test";

#define TRY_DECRYPT(expect, expect_size, ciphertext, ciphertext_size) \
    do { \
        if (try_decrypt(expect, expect_size, ciphertext, ciphertext_size, __FILE__, __LINE__)) { \
            return 1; \
        } \
    } while (0)

static uint8_t recv_buf[65536];
static size_t recv_buf_used;
static const uint8_t *post_buf;
static size_t post_buf_remain;

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)userdata;

    // CURL limits the total size passed, so this won't overflow
    size_t total_size = size * nmemb;

    if (total_size > sizeof(recv_buf) - recv_buf_used) {
        // Too much data for the recv_buf. Signal an error to curl by returning less
        // than the amount of data given.
        return 0;
    }

    memcpy(recv_buf + recv_buf_used, ptr, total_size);
    recv_buf_used += total_size;

    return total_size;
}

static size_t read_callback(char *buffer, size_t size, size_t nitems, void *instream) {
    (void)instream;

    // size, nitems are trusted values from curl
    size_t limit = size * nitems;

    if (limit > post_buf_remain) {
        limit = post_buf_remain;
    }

    memcpy(buffer, post_buf, limit);
    post_buf += limit;
    post_buf_remain -= limit;

    return limit;
}


static CURL *curl;
static struct curl_slist *headers;
static char curl_error_buf[CURL_ERROR_SIZE];

static void curl_init() {
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Curl initialization failed\n");
        exit(1);
    }

    curl_easy_setopt(curl, CURLOPT_URL, apigw_url);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

    // We're sending a raw buffer as the body of the HTTP request, not an HTML form body.
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, NULL);

    headers = curl_slist_append(NULL, "Transfer-Encoding: chunked");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error_buf);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L);
}

static void curl_clean_up() {
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
}

static int try_decrypt(
    const uint8_t *expected,
    size_t expected_size,
    const uint8_t *ciphertext,
    size_t ciphertext_size,
    const char *file,
    int line
) {
    (void)line; (void)file;

    post_buf = ciphertext;
    post_buf_remain = ciphertext_size;
    recv_buf_used = 0;

    CURLcode result = curl_easy_perform(curl);

    if (result != CURLE_OK) {
        fprintf(stderr, "CURL error: %s\n", curl_error_buf);
        return 1;
    }

    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200L) {
        fprintf(stderr, "Error from server (code %ld):\n", http_code);
        fwrite(recv_buf, recv_buf_used, 1, stderr);
        fprintf(stderr, "\n");
        return 1;
    }

    if (expected_size != recv_buf_used || memcmp(expected, recv_buf, recv_buf_used)) {
        fprintf(stderr, "Plaintext mismatch; expected:\n");
        hexdump(stderr, expected, expected_size);
        fprintf(stderr, "actual:\n");
        hexdump(stderr, recv_buf, recv_buf_used);
        return 1;
    }

    return 0;
}

static int test_basic() {
    uint8_t plaintext[] = "Hello, world!";

    uint8_t ciphertext[1024];

    size_t pt_consumed, ct_consumed;

    struct aws_cryptosdk_session *session;
    struct aws_cryptosdk_cmm *cmm = NULL;

    if (!(cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), aws_cryptosdk_zero_keyring_new()))) abort();
    if (aws_cryptosdk_default_cmm_set_alg_id(cmm, alg_to_use)) abort();
    if (!(session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm))) abort();

    aws_cryptosdk_session_set_message_size(session, sizeof(plaintext));
    
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session,
        ciphertext, sizeof(ciphertext), &ct_consumed,
        plaintext, sizeof(plaintext), &pt_consumed
    ));

    TEST_ASSERT_INT_EQ(pt_consumed, sizeof(plaintext));
    TEST_ASSERT(aws_cryptosdk_session_is_done(session));

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_cmm_destroy(cmm);

    hexdump(stderr, ciphertext, ct_consumed);

    TRY_DECRYPT(plaintext, sizeof(plaintext), ciphertext, ct_consumed);

    return 0;
}

static int test_framesize(size_t plaintext_sz, size_t framesize, bool early_size) {
    uint8_t *plaintext = malloc(plaintext_sz);
    aws_cryptosdk_genrandom(plaintext, plaintext_sz);

    uint8_t *ciphertext = malloc(plaintext_sz);
    size_t ciphertext_buf_sz = plaintext_sz;

    struct aws_cryptosdk_session *session;
    struct aws_cryptosdk_cmm *cmm = NULL;

    if (!(cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), aws_cryptosdk_zero_keyring_new()))) abort();
    if (aws_cryptosdk_default_cmm_set_alg_id(cmm, alg_to_use)) abort();
    if (!(session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm))) abort();

    if (early_size) aws_cryptosdk_session_set_message_size(session, plaintext_sz);
    aws_cryptosdk_session_set_frame_size(session, framesize);

    size_t pt_offset = 0, ct_offset = 0;

    while (!aws_cryptosdk_session_is_done(session)) {
        size_t pt_need, ct_need;
        aws_cryptosdk_session_estimate_buf(session, &ct_need, &pt_need);

        size_t pt_available = plaintext_sz - pt_offset;
        if (pt_need < pt_available) pt_available = pt_need;

        const uint8_t *pt_ptr = &plaintext[pt_offset];

        size_t ct_available = ct_need;
        if (ct_offset + ct_need > ciphertext_buf_sz) {
            ciphertext_buf_sz = ct_offset + ct_need;
            ciphertext = realloc(ciphertext, ciphertext_buf_sz);
        }
        uint8_t *ct_ptr = &ciphertext[ct_offset];

        size_t pt_consumed, ct_generated;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(session,
            ct_ptr, ct_need, &ct_generated,
            pt_ptr, pt_available, &pt_consumed
        ));

        // Estimates can be off until the first call to process. We'll check
        // that we're making progress by re-estimating after calling process;
        // if we made no progress and the estimate is asking for more plaintext
        // than our limit, then something is wrong.
        aws_cryptosdk_session_estimate_buf(session, &ct_need, &pt_need);

        if (pt_need > plaintext_sz - pt_offset && ct_need <= ct_available && !pt_consumed && !ct_generated) {
            // Hmm... it seems to want more plaintext than we have available.
            // If we haven't set the precise size yet, then this is
            // understandable; it's also possible that we've not gotten to the
            // body yet, in which case we should see insufficient ciphertext
            // space. Otherwise something has gone wrong.

            TEST_ASSERT(!early_size);
            aws_cryptosdk_session_set_message_size(session, plaintext_sz);
        }

        pt_offset += pt_consumed;
        ct_offset += ct_generated;
    }

    TRY_DECRYPT(plaintext, plaintext_sz, ciphertext, ct_offset);

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_cmm_destroy(cmm);

    free(plaintext);
    free(ciphertext);

    return 0;
}

int main() {
    aws_load_error_strings();
    aws_cryptosdk_err_init_strings();

    curl_init();

    int final_result = 0;

    for (size_t i = 0; i < sizeof(known_algorithms)/sizeof(*known_algorithms); i++) {
        alg_to_use = known_algorithms[i];
        fprintf(stderr, "Testing algorithm %s...\n",
            aws_cryptosdk_alg_props(alg_to_use)->alg_name
        );

        RUN_TEST(test_basic());
        RUN_TEST(test_framesize(0, 1024, true));
        RUN_TEST(test_framesize(0, 1024, false));
        RUN_TEST(test_framesize(1, 1, true));
        RUN_TEST(test_framesize(1, 1, false));
        RUN_TEST(test_framesize(1024, 1024, true));
        RUN_TEST(test_framesize(1024, 1024, false));
        RUN_TEST(test_framesize(1023, 1024, true));
        RUN_TEST(test_framesize(1023, 1024, false));
        RUN_TEST(test_framesize(1025, 1024, true));
        RUN_TEST(test_framesize(1025, 1024, false));
        RUN_TEST(test_framesize(0, 0, true));
        RUN_TEST(test_framesize(1, 0, true));
        RUN_TEST(test_framesize(1024, 0, true));
    }
    curl_clean_up();

    return final_result;
}
