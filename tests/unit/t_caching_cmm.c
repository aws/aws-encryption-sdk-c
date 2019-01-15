/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/session.h>

#include <aws/common/encoding.h>

#include <stdarg.h>

#include "cache_test_lib.h"
#include "counting_keyring.h"
#include "testing.h"
#include "testutil.h"
#include "zero_keyring.h"

/*
 * Pointers to the underlying mocks set up by setup_mocks.
 */
static struct mock_materials_cache *mock_materials_cache;
static struct mock_upstream_cmm *mock_upstream_cmm;
/*
 * Typecasted pointers to the mocks. These pointers are considered
 * to hold a reference; to test that the caching CMM holds a reference,
 * call release_mocks(), which releases these and nulls them out.
 */
static struct aws_cryptosdk_materials_cache *materials_cache;
static struct aws_cryptosdk_cmm *cmm;

static void setup_mocks();
static void teardown();
static void release_mocks();

static int create_destroy() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    aws_cryptosdk_cmm_release(cmm);
    teardown();

    return 0;
}

static int enc_cache_miss() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    struct aws_hash_table req_context, expect_context;
    aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &req_context);
    aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &expect_context);

    struct aws_cryptosdk_enc_request request;
    request.alloc          = aws_default_allocator();
    request.requested_alg  = 0;
    request.plaintext_size = 32768;

    struct aws_cryptosdk_enc_materials *output, *expected;

    mock_upstream_cmm->n_edks       = 5;
    mock_upstream_cmm->returned_alg = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

    request.enc_ctx = &expect_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(&mock_upstream_cmm->base, &expected, &request));

    request.enc_ctx = &req_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(cmm, &output, &request));

    /* Materials should match those returned from the upstream */
    TEST_ASSERT(materials_eq(output, expected));
    TEST_ASSERT(aws_hash_table_eq(&req_context, &expect_context, aws_hash_callback_string_eq));
    /* The upstream CMM should see the original request */
    TEST_ASSERT_ADDR_EQ(mock_upstream_cmm->last_enc_request, &request);
    /* We should have inserted the result into the cache */
    TEST_ASSERT(materials_eq(output, mock_materials_cache->enc_materials));
    TEST_ASSERT(
        aws_hash_table_eq(&req_context, &mock_materials_cache->encryption_context, aws_hash_callback_string_eq));
    TEST_ASSERT_INT_EQ(request.plaintext_size, mock_materials_cache->usage_stats.bytes_encrypted);
    TEST_ASSERT_INT_EQ(1, mock_materials_cache->usage_stats.messages_encrypted);

    aws_cryptosdk_enc_ctx_clean_up(&req_context);
    aws_cryptosdk_enc_ctx_clean_up(&expect_context);
    aws_cryptosdk_enc_materials_destroy(output);
    aws_cryptosdk_enc_materials_destroy(expected);

    aws_cryptosdk_cmm_release(cmm);
    teardown();

    return 0;
}

static int enc_cache_hit() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    struct aws_hash_table req_context, expect_context;
    aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &req_context);
    aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &expect_context);

    struct aws_cryptosdk_enc_request request;
    request.alloc          = aws_default_allocator();
    request.requested_alg  = 0;
    request.plaintext_size = 32768;

    struct aws_cryptosdk_enc_materials *output, *expected;

    mock_upstream_cmm->n_edks       = 5;
    mock_upstream_cmm->returned_alg = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

    request.enc_ctx = &expect_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(&mock_upstream_cmm->base, &expected, &request));

    /* Perform a cache miss to initialize things... */
    request.enc_ctx = &req_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(cmm, &output, &request));
    mock_materials_cache->usage_stats.bytes_encrypted = 42;
    mock_materials_cache->should_hit                  = true;
    aws_cryptosdk_enc_materials_destroy(output);

    struct aws_byte_buf cache_id_buf;
    TEST_ASSERT_SUCCESS(
        aws_byte_buf_init_copy(&cache_id_buf, aws_default_allocator(), &mock_materials_cache->last_cache_id));

    /* this should stay null after a hit */
    mock_upstream_cmm->last_enc_request = NULL;
    aws_hash_table_clear(&req_context);

    /* This should be a hit */
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(cmm, &output, &request));

    /* Materials should match those returned from the upstream */
    TEST_ASSERT(materials_eq(output, expected));
    TEST_ASSERT(aws_hash_table_eq(&req_context, &expect_context, aws_hash_callback_string_eq));

    /* The upstream CMM should not see the original request */
    TEST_ASSERT_ADDR_EQ(mock_upstream_cmm->last_enc_request, NULL);

    /* We should have updated the usage stats */
    TEST_ASSERT_INT_EQ(request.plaintext_size + 42, mock_materials_cache->usage_stats.bytes_encrypted);
    TEST_ASSERT_INT_EQ(2, mock_materials_cache->usage_stats.messages_encrypted);

    /* Same cache ID should have been seen */
    TEST_ASSERT(aws_byte_buf_eq(&cache_id_buf, &mock_materials_cache->last_cache_id));

    aws_cryptosdk_enc_ctx_clean_up(&req_context);
    aws_cryptosdk_enc_ctx_clean_up(&expect_context);
    aws_cryptosdk_enc_materials_destroy(output);
    aws_cryptosdk_enc_materials_destroy(expected);
    aws_byte_buf_clean_up(&cache_id_buf);

    aws_cryptosdk_cmm_release(cmm);
    teardown();

    return 0;
}

static int enc_cache_unique_ids() {
    struct aws_allocator *alloc = aws_default_allocator();
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    struct aws_hash_table req_context, output_context, seen_ids;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &req_context));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &output_context));
    TEST_ASSERT_SUCCESS(aws_hash_table_init(
        &seen_ids,
        aws_default_allocator(),
        16,
        aws_hash_string,
        aws_hash_callback_string_eq,
        aws_hash_callback_string_destroy,
        NULL));

    struct aws_cryptosdk_enc_request request;
    request.alloc          = aws_default_allocator();
    request.requested_alg  = 0;
    request.plaintext_size = 32768;
    request.enc_ctx        = &req_context;

    mock_upstream_cmm->n_edks       = 1;
    mock_upstream_cmm->returned_alg = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;

#define ASSERT_UNIQUE_ID(is_unique)                                                                               \
    do {                                                                                                          \
        TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_clone(aws_default_allocator(), &output_context, &req_context)); \
        if (request.requested_alg) mock_upstream_cmm->returned_alg = request.requested_alg;                       \
        struct aws_cryptosdk_enc_materials *materials = NULL;                                                     \
        TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(cmm, &materials, &request));                 \
        aws_cryptosdk_enc_materials_destroy(materials);                                                           \
        struct aws_string *cache_id = aws_string_new_from_array(                                                  \
            aws_default_allocator(),                                                                              \
            mock_materials_cache->last_cache_id.buffer,                                                           \
            mock_materials_cache->last_cache_id.len);                                                             \
        int was_created;                                                                                          \
        TEST_ASSERT_SUCCESS(aws_hash_table_put(&seen_ids, cache_id, NULL, &was_created));                         \
        TEST_ASSERT_INT_EQ(was_created, is_unique);                                                               \
    } while (0)

    ASSERT_UNIQUE_ID(true);

    request.requested_alg = ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    ASSERT_UNIQUE_ID(true);

    request.requested_alg = ALG_AES256_GCM_IV12_TAG16_NO_KDF;
    ASSERT_UNIQUE_ID(true);

    // Changing the plaintext size should not change the cache ID
    request.plaintext_size = 65536;

    ASSERT_UNIQUE_ID(false);

    // Changing the context should change the cache ID
    TEST_ASSERT_SUCCESS(aws_hash_table_put(
        &req_context, aws_string_new_from_c_str(alloc, "foo"), aws_string_new_from_c_str(alloc, "bar"), NULL));
    ASSERT_UNIQUE_ID(true);

    TEST_ASSERT_SUCCESS(aws_hash_table_put(
        &req_context, aws_string_new_from_c_str(alloc, "foo"), aws_string_new_from_c_str(alloc, "baz"), NULL));
    ASSERT_UNIQUE_ID(true);

    aws_hash_table_clear(&req_context);
    // Hash keys are used in the cache ID computation, not just values
    TEST_ASSERT_SUCCESS(aws_hash_table_put(
        &req_context, aws_string_new_from_c_str(alloc, "foobar"), aws_string_new_from_c_str(alloc, "bar"), NULL));
    ASSERT_UNIQUE_ID(true);

    // The cache ID calculation looks at multiple hash entries
    TEST_ASSERT_SUCCESS(aws_hash_table_put(
        &req_context, aws_string_new_from_c_str(alloc, "foo"), aws_string_new_from_c_str(alloc, "bar"), NULL));
    ASSERT_UNIQUE_ID(true);

    aws_hash_table_clean_up(&seen_ids);
    aws_hash_table_clean_up(&output_context);
    aws_hash_table_clean_up(&req_context);

    aws_cryptosdk_cmm_release(cmm);

    teardown();

    return 0;
}

struct aws_string *hash_or_generate_partition_id(struct aws_allocator *alloc, const struct aws_byte_buf *partition_id);
int hash_enc_request(
    struct aws_string *partition_id, struct aws_byte_buf *out, const struct aws_cryptosdk_enc_request *req);

static int encrypt_id_vector(
    const char *expected_b64,
    const char *partition_name,
    enum aws_cryptosdk_alg_id requested_alg,
    /* k, v, k, v, NULL */...) {
    struct aws_byte_buf partition_name_buf = aws_byte_buf_from_c_str(partition_name);
    struct aws_string *partition_id = hash_or_generate_partition_id(aws_default_allocator(), &partition_name_buf);
    TEST_ASSERT_ADDR_NOT_NULL(partition_id);

    struct aws_byte_buf expected, actual;

    expected = easy_b64_decode(expected_b64);
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(&actual, aws_default_allocator(), expected.len));

    struct aws_cryptosdk_enc_request request;
    struct aws_hash_table encryption_context;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &encryption_context));

    request.alloc          = aws_default_allocator();
    request.plaintext_size = 0;
    request.requested_alg  = requested_alg;
    request.enc_ctx        = &encryption_context;

    va_list args;
    va_start(args, requested_alg);

    while (true) {
        const char *k = va_arg(args, const char *);
        if (!k) break;
        const char *v = va_arg(args, const char *);
        assert(v);

        struct aws_string *sk = aws_string_new_from_c_str(aws_default_allocator(), k);
        struct aws_string *sv = aws_string_new_from_c_str(aws_default_allocator(), v);

        TEST_ASSERT_SUCCESS(aws_hash_table_put(&encryption_context, sk, sv, NULL));
    }

    TEST_ASSERT_SUCCESS(hash_enc_request(partition_id, &actual, &request));

    TEST_ASSERT(aws_byte_buf_eq(&expected, &actual));

    aws_cryptosdk_enc_ctx_clean_up(&encryption_context);
    aws_byte_buf_clean_up(&expected);
    aws_byte_buf_clean_up(&actual);
    aws_string_destroy(partition_id);

    return 0;
}

static int enc_cache_id_test_vecs() {
    const char *partition_name = "c15b9079-6d0e-42b6-8784-5e804b025692";
    TEST_ASSERT(
        0 == encrypt_id_vector(
                 "rkrFAso1YyPbOJbmwVMjrPw+wwLJT7xusn8tA8zMe9e3+OqbtfDueB7bvoKLU3fsmdUvZ6eMt7mBp1ThMMB25Q==",
                 partition_name,
                 0,
                 NULL));

    TEST_ASSERT(
        0 == encrypt_id_vector(
                 "3icBIkLK4V3fVwbm3zSxUdUQV6ZvZYUOLl8buN36g6gDMqAkghcGryxX7QiVABkW1JhB6GRp5z+bzbiuciBcKQ==",
                 partition_name,
                 ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                 NULL));

#define CONTEXT_FULL "this", "is", "a", "non-empty", "encryption", "context", NULL

    TEST_ASSERT(
        0 == encrypt_id_vector(
                 "IHiUHYOUVUEFTc3BcZPJDlsWct2Qy1A7JdfQl9sQoV/ILIbRpoz9q7RtGd/MlibaGl5ihE66cN8ygM8A5rtYbg==",
                 partition_name,
                 0,
                 CONTEXT_FULL));

    TEST_ASSERT(
        0 == encrypt_id_vector(
                 "mRNK7qhTb/kJiiyGPgAevp0gwFRcET4KeeNYwZHhoEDvSUzQiDgl8Of+YRDaVzKxAqpNBgcAuFXde9JlaRRsmw==",
                 partition_name,
                 ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                 CONTEXT_FULL));

    return 0;
}

static int access_cache(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_enc_request *request,
    bool *was_hit,
    struct aws_cryptosdk_cache_usage_stats usag) {
    mock_upstream_cmm->n_edks        = 1;
    mock_upstream_cmm->returned_alg  = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256;
    mock_materials_cache->should_hit = mock_materials_cache->enc_materials != NULL;

    mock_upstream_cmm->last_enc_request = NULL;
    mock_materials_cache->invalidated   = false;

    struct aws_cryptosdk_enc_materials *output;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(cmm, &output, request));

    *was_hit = !mock_upstream_cmm->last_enc_request;

    aws_cryptosdk_enc_materials_destroy(output);

    return 0;
}

static uint64_t mock_clock_time = 0;
static bool mock_clock_queried;
static int mock_clock_get_ticks(uint64_t *now) {
    *now               = mock_clock_time;
    mock_clock_queried = true;
    return 0;
}
void caching_cmm_set_clock(struct aws_cryptosdk_cmm *generic_cmm, int (*clock_get_ticks)(uint64_t *now));

#define ASSERT_HIT(should_hit)                              \
    do {                                                    \
        request.enc_ctx = &req_context;                     \
        aws_hash_table_clear(&req_context);                 \
        if (access_cache(cmm, &request, &was_hit, usage)) { \
            return 1;                                       \
        }                                                   \
        TEST_ASSERT_INT_EQ(should_hit, was_hit);            \
    } while (0)

static int limits_test() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, NULL);

    struct aws_hash_table req_context;
    aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &req_context);

    struct aws_cryptosdk_enc_request request;
    request.alloc          = aws_default_allocator();
    request.requested_alg  = 0;
    request.plaintext_size = 32768;

    bool was_hit;
    struct aws_cryptosdk_cache_usage_stats usage = { 1, 1 };

    // Set a sentinel value so we know if the CMM set a TTL hint when it shouldn't
    mock_materials_cache->entry_ttl_hint = 0x424242;
    mock_clock_queried                   = false;
    caching_cmm_set_clock(cmm, mock_clock_get_ticks);

    // Do an initial miss to create the response
    ASSERT_HIT(false);

    // Sanity check: We should hit
    ASSERT_HIT(true);

    // If we set a message use limit, we'll expire after we hit the limit
    TEST_ASSERT_SUCCESS(aws_cryptosdk_caching_cmm_set_limits(cmm, AWS_CRYPTOSDK_CACHE_LIMIT_MESSAGES, 4));
    mock_materials_cache->usage_stats.messages_encrypted = 2;
    ASSERT_HIT(true);
    TEST_ASSERT(!mock_materials_cache->invalidated);
    mock_materials_cache->usage_stats.messages_encrypted = 3;
    ASSERT_HIT(true);
    TEST_ASSERT(mock_materials_cache->invalidated);
    mock_materials_cache->usage_stats.messages_encrypted = 4;
    ASSERT_HIT(false);
    TEST_ASSERT(mock_materials_cache->invalidated);
    // Note that our mock doesn't actually invalidate when asked, so we can continue on

    // The caching CMM should clamp the message limit to 1<<32
    TEST_ASSERT_SUCCESS(aws_cryptosdk_caching_cmm_set_limits(cmm, AWS_CRYPTOSDK_CACHE_LIMIT_MESSAGES, UINT64_MAX));
    mock_materials_cache->usage_stats.messages_encrypted = AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES - 1;
    ASSERT_HIT(true);
    mock_materials_cache->usage_stats.messages_encrypted = AWS_CRYPTOSDK_CACHE_MAX_LIMIT_MESSAGES;
    ASSERT_HIT(false);

    // Byte limits next
    mock_materials_cache->usage_stats.messages_encrypted = 0;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_caching_cmm_set_limits(cmm, AWS_CRYPTOSDK_CACHE_LIMIT_BYTES, 1000));

    request.plaintext_size                            = 250;
    mock_materials_cache->usage_stats.bytes_encrypted = 250;
    ASSERT_HIT(true);

    request.plaintext_size                            = 500;
    mock_materials_cache->usage_stats.bytes_encrypted = 500;
    ASSERT_HIT(true);
    // Request should have invalidated this entry, but still hit
    TEST_ASSERT(mock_materials_cache->invalidated);

    request.plaintext_size                            = 501;
    mock_materials_cache->usage_stats.bytes_encrypted = 500;
    ASSERT_HIT(false);
    TEST_ASSERT(mock_materials_cache->invalidated);

    request.plaintext_size                            = 1;
    mock_materials_cache->usage_stats.bytes_encrypted = 1000;
    ASSERT_HIT(false);
    TEST_ASSERT(mock_materials_cache->invalidated);

    // TTL limits
    // Since we had no limit set until now, the CMM should not have been querying the clock
    // or setting TTLs
    TEST_ASSERT(!mock_clock_queried);
    TEST_ASSERT_INT_EQ(mock_materials_cache->entry_ttl_hint, 0x424242);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_caching_cmm_set_limits(cmm, AWS_CRYPTOSDK_CACHE_LIMIT_BYTES, UINT64_MAX));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_caching_cmm_set_limits(cmm, AWS_CRYPTOSDK_CACHE_LIMIT_TTL, 10000));
    mock_materials_cache->usage_stats.bytes_encrypted = 0;

    mock_clock_time                           = 100;
    mock_materials_cache->entry_creation_time = 1;
    ASSERT_HIT(true);
    TEST_ASSERT_INT_EQ(10001, mock_materials_cache->entry_ttl_hint);
    TEST_ASSERT(!mock_materials_cache->invalidated);

    mock_clock_time                      = 200;
    mock_materials_cache->entry_ttl_hint = 0;
    ASSERT_HIT(true);
    TEST_ASSERT_INT_EQ(10001, mock_materials_cache->entry_ttl_hint);
    TEST_ASSERT(!mock_materials_cache->invalidated);

    mock_clock_time                      = 10000;
    mock_materials_cache->entry_ttl_hint = 0;
    ASSERT_HIT(true);
    TEST_ASSERT_INT_EQ(10001, mock_materials_cache->entry_ttl_hint);
    TEST_ASSERT(!mock_materials_cache->invalidated);

    mock_materials_cache->entry_ttl_hint = 0;
    mock_clock_time                      = 10001;
    ASSERT_HIT(false);
    TEST_ASSERT(mock_materials_cache->invalidated);
    // At this point our mock clock time is 10001, and we had a cache miss.
    // We'd expect that, since our TTL is 10000, we should get a TTL hint of
    // 20001; however, the mock_materials_cache's entry creation time is still set
    // to 1 (even after the miss, because the mock cache doesn't know about our
    // fake clock), so the TTL hint ends up being 10001.
    TEST_ASSERT_INT_EQ(10001, mock_materials_cache->entry_ttl_hint);

    mock_materials_cache->entry_creation_time = 1;
    mock_clock_time                           = 10002;
    ASSERT_HIT(false);
    TEST_ASSERT(mock_materials_cache->invalidated);

    // If someone sets a really big timeout, and the expiration overflows, we shouldn't
    // expire.
    mock_materials_cache->entry_creation_time = (uint64_t)0xE << 60;  // 0xE000....ULL
    TEST_ASSERT_SUCCESS(aws_cryptosdk_caching_cmm_set_limits(cmm, AWS_CRYPTOSDK_CACHE_LIMIT_TTL, (uint64_t)0x2 << 60));
    mock_clock_time = 2;

    mock_materials_cache->entry_ttl_hint = 0x424242;
    ASSERT_HIT(true);
    TEST_ASSERT_INT_EQ(mock_materials_cache->entry_ttl_hint, 0x424242);

    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_enc_ctx_clean_up(&req_context);
    teardown();

    return 0;
}

int hash_dec_request(
    const struct aws_string *partition_id, struct aws_byte_buf *out, const struct aws_cryptosdk_dec_request *req);

static int dec_test_vector(
    const char *partition_name,
    enum aws_cryptosdk_alg_id alg,
    const struct aws_cryptosdk_edk *edk_list,
    size_t n_edks,
    struct aws_hash_table *enc_ctx,
    const char *expected_b64) {
    struct aws_byte_buf partition_name_buf = aws_byte_buf_from_c_str(partition_name);
    struct aws_string *partition_id = hash_or_generate_partition_id(aws_default_allocator(), &partition_name_buf);

    struct aws_byte_buf expected, actual;

    expected = easy_b64_decode(expected_b64);
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(&actual, aws_default_allocator(), expected.len));

    struct aws_cryptosdk_dec_request request;
    request.alloc   = aws_default_allocator();
    request.alg     = alg;
    request.enc_ctx = enc_ctx;

    aws_array_list_init_static(&request.encrypted_data_keys, (void *)edk_list, n_edks, sizeof(*edk_list));
    request.encrypted_data_keys.length = n_edks;

    TEST_ASSERT_SUCCESS(hash_dec_request(partition_id, &actual, &request));
    TEST_ASSERT(aws_byte_buf_eq(&expected, &actual));

    aws_byte_buf_clean_up(&expected);
    aws_byte_buf_clean_up(&actual);
    aws_string_destroy(partition_id);

    return 0;
}

static int dec_cache_id_test_vecs() {
    struct aws_cryptosdk_edk test_edks[4];

    test_edks[0].provider_id   = aws_byte_buf_from_c_str("this is a provider ID");
    test_edks[0].provider_info = aws_byte_buf_from_c_str("this is some key info");
    test_edks[0].ciphertext    = aws_byte_buf_from_c_str("super secret key, now with encryption!");
    test_edks[1].provider_id   = aws_byte_buf_from_c_str("another provider ID!");
    test_edks[1].provider_info = aws_byte_buf_from_c_str("this is some different key info");
    test_edks[1].ciphertext    = aws_byte_buf_from_c_str("better super secret key, now with encryption!");

    struct aws_hash_table enc_ctx;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &enc_ctx));

    TEST_ASSERT_INT_EQ(
        0,
        dec_test_vector(
            "c15b9079-6d0e-42b6-8784-5e804b025692",
            ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
            &test_edks[0],
            1,
            &enc_ctx,
            "n0zVzk9QIVxhz6ET+aJIKKOJNxtpGtSe1yAbu7WU5l272Iw/jmhlER4psDHJs9Mr8KYiIvLGSXzggNDCc23+9w=="));

#define STATIC_PUT(hk, k, v)                                                                         \
    do {                                                                                             \
        AWS_STATIC_STRING_FROM_LITERAL(STATIC_KEY, k);                                               \
        AWS_STATIC_STRING_FROM_LITERAL(STATIC_VAL, v);                                               \
        TEST_ASSERT_SUCCESS(aws_hash_table_put((hk), (void *)STATIC_KEY, (void *)STATIC_VAL, NULL)); \
    } while (0)

    STATIC_PUT(&enc_ctx, "this", "is");
    STATIC_PUT(&enc_ctx, "a", "non-empty");
    STATIC_PUT(&enc_ctx, "encryption", "context");

    TEST_ASSERT_INT_EQ(
        0,
        dec_test_vector(
            "c15b9079-6d0e-42b6-8784-5e804b025692",
            ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            &test_edks[0],
            2,
            &enc_ctx,
            "+rtwUe38CGnczGmYu12iqGWHIyDyZ44EvYQ4S6ACmsgS8VaEpiw0RTGpDk6Z/7YYN/jVHOAcNKDyCNP8EmstFg=="));

    test_edks[0].provider_id   = aws_byte_buf_from_array((const uint8_t *)"", 0);
    test_edks[0].provider_info = aws_byte_buf_from_array((const uint8_t *)"", 0);
    test_edks[0].ciphertext    = aws_byte_buf_from_array((const uint8_t *)"", 0);
    test_edks[1].provider_id   = aws_byte_buf_from_array((const uint8_t *)"\0", 1);
    test_edks[1].provider_info = aws_byte_buf_from_array((const uint8_t *)"\0", 1);
    test_edks[1].ciphertext    = aws_byte_buf_from_array((const uint8_t *)"\0", 1);
    test_edks[2].provider_id   = aws_byte_buf_from_c_str("\xc2\x81");
    test_edks[2].provider_info = aws_byte_buf_from_c_str("\x81");
    test_edks[2].ciphertext    = aws_byte_buf_from_c_str("\x81");
    test_edks[3].provider_id   = aws_byte_buf_from_c_str("abc");
    test_edks[3].provider_info = aws_byte_buf_from_c_str("\xde\xad\xbe\xef");
    test_edks[3].ciphertext    = aws_byte_buf_from_c_str("\xba\xd0\xca\xfe");

    aws_hash_table_clear(&enc_ctx);

    STATIC_PUT(&enc_ctx, "\0\0TEST", "\0\0test");
    STATIC_PUT(&enc_ctx, "\xf0\x90\x80\x80", "UTF-16 surrogate");
    STATIC_PUT(&enc_ctx, "\xea\xaf\x8d", "\\uABCD");

    TEST_ASSERT_INT_EQ(
        0,
        dec_test_vector(
            "partition ID",
            ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
            test_edks,
            4,
            &enc_ctx,
            "4WNEY0NQ/oy1HmnsTgaByErH7y30J71N5K77680+rSKV8bFamM5gaZ4O+/adu8EuJVKxbv+Epum1dm7k1pp4lw=="));

    aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);

    return 0;
}

static int dec_materials() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, NULL);
    caching_cmm_set_clock(cmm, mock_clock_get_ticks);

    struct aws_hash_table enc_ctx;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &enc_ctx));

    struct aws_cryptosdk_edk edk;
    edk.provider_id   = aws_byte_buf_from_c_str("provider_id");
    edk.provider_info = aws_byte_buf_from_c_str("provider_info");
    edk.ciphertext    = aws_byte_buf_from_c_str("enc_data_key");

    struct aws_cryptosdk_dec_request dec_request = { 0 };
    dec_request.alloc                            = aws_default_allocator();
    dec_request.alg                              = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    dec_request.enc_ctx                          = &enc_ctx;
    aws_array_list_init_static(&dec_request.encrypted_data_keys, &edk, 1, sizeof(edk));

    struct aws_cryptosdk_dec_materials *miss_materials = NULL, *hit_materials = NULL;

    mock_clock_time                           = 0;
    mock_materials_cache->entry_ttl_hint      = 0x424242;
    mock_materials_cache->entry_creation_time = 0;
    /* Basic cache miss (no limits configured, no signature keys) */
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_decrypt_materials(cmm, &miss_materials, &dec_request));
    TEST_ASSERT(mock_materials_cache->dec_materials);
    TEST_ASSERT_ADDR_EQ(mock_upstream_cmm->last_dec_request, &dec_request);
    TEST_ASSERT_INT_EQ(mock_materials_cache->entry_ttl_hint, 0x424242);

    /* Basic cache hit */
    mock_materials_cache->should_hit    = true;
    mock_upstream_cmm->last_dec_request = NULL;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_decrypt_materials(cmm, &hit_materials, &dec_request));
    TEST_ASSERT(dec_materials_eq(miss_materials, hit_materials));
    TEST_ASSERT(same_signing_key(miss_materials->signctx, hit_materials->signctx));
    TEST_ASSERT_ADDR_NULL(mock_upstream_cmm->last_dec_request);

    /* Hit; TTL OK */
    aws_cryptosdk_caching_cmm_set_limits(cmm, AWS_CRYPTOSDK_CACHE_LIMIT_TTL, 100);
    mock_clock_time = 99;
    aws_cryptosdk_dec_materials_destroy(hit_materials);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_decrypt_materials(cmm, &hit_materials, &dec_request));
    TEST_ASSERT(dec_materials_eq(miss_materials, hit_materials));
    TEST_ASSERT_ADDR_NULL(mock_upstream_cmm->last_dec_request);

    /* Miss; TTL expired */
    aws_cryptosdk_dec_materials_destroy(miss_materials);
    mock_clock_time = 101;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_decrypt_materials(cmm, &miss_materials, &dec_request));
    /* signature key should have changed due to behavior of the mock upstream cmm */
    TEST_ASSERT_ADDR_NOT_NULL(mock_upstream_cmm->last_dec_request);

    // At this point our mock clock time is 101, and we had a cache miss.
    // We'd expect that, since our TTL is 100, we should get a TTL hint of
    // 201; however, the mock_materials_cache's entry creation time is still set
    // to 0 (even after the miss, because the mock cache doesn't know about our
    // fake clock), so the TTL hint ends up being 100.
    TEST_ASSERT_INT_EQ(mock_materials_cache->entry_ttl_hint, 100);
    TEST_ASSERT(!same_signing_key(miss_materials->signctx, hit_materials->signctx));

    aws_cryptosdk_dec_materials_destroy(miss_materials);
    aws_cryptosdk_dec_materials_destroy(hit_materials);

    aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);
    aws_cryptosdk_cmm_release(cmm);
    teardown();

    return 0;
}

static int cache_miss_failed_put() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, NULL);
    caching_cmm_set_clock(cmm, mock_clock_get_ticks);

    struct aws_hash_table enc_ctx;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &enc_ctx));

    struct aws_cryptosdk_edk edk;
    edk.provider_id   = aws_byte_buf_from_c_str("provider_id");
    edk.provider_info = aws_byte_buf_from_c_str("provider_info");
    edk.ciphertext    = aws_byte_buf_from_c_str("enc_data_key");

    struct aws_cryptosdk_dec_request dec_request = { 0 };
    dec_request.alloc                            = aws_default_allocator();
    dec_request.alg                              = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    dec_request.enc_ctx                          = &enc_ctx;
    aws_array_list_init_static(&dec_request.encrypted_data_keys, &edk, 1, sizeof(edk));

    struct aws_cryptosdk_enc_request enc_request;
    enc_request.alloc          = aws_default_allocator();
    enc_request.requested_alg  = 0;
    enc_request.plaintext_size = 32768;
    enc_request.enc_ctx        = &enc_ctx;

    mock_materials_cache->should_fail = true;
    mock_upstream_cmm->returned_alg   = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256;

    struct aws_cryptosdk_enc_materials *enc_materials;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_enc_materials(cmm, &enc_materials, &enc_request));
    aws_cryptosdk_enc_materials_destroy(enc_materials);

    struct aws_cryptosdk_dec_materials *dec_materials;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_decrypt_materials(cmm, &dec_materials, &dec_request));
    aws_cryptosdk_dec_materials_destroy(dec_materials);

    aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);
    aws_cryptosdk_cmm_release(cmm);
    teardown();

    return 0;
}

static bool partitions_match_on_enc(
    const struct aws_byte_buf *partition_name_a, const struct aws_byte_buf *partition_name_b) {
    struct aws_cryptosdk_cmm *cmm_a = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, partition_name_a);
    struct aws_cryptosdk_cmm *cmm_b = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, partition_name_b);

    struct aws_hash_table enc_ctx;
    if (aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &enc_ctx)) {
        abort();
    }

    struct aws_cryptosdk_enc_request enc_request;
    enc_request.alloc          = aws_default_allocator();
    enc_request.requested_alg  = 0;
    enc_request.plaintext_size = 32768;
    enc_request.enc_ctx        = &enc_ctx;

    mock_upstream_cmm->returned_alg = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256;

    struct aws_cryptosdk_enc_materials *materials;
    if (aws_cryptosdk_cmm_generate_enc_materials(cmm_a, &materials, &enc_request)) {
        abort();
    }
    aws_cryptosdk_enc_materials_destroy(materials);

    struct aws_byte_buf cache_id_a = mock_materials_cache->last_cache_id;
    // Prevent the cache ID from being freed on the next call
    mock_materials_cache->last_cache_id = aws_byte_buf_from_c_str("");

    aws_hash_table_clear(&enc_ctx);
    if (aws_cryptosdk_cmm_generate_enc_materials(cmm_b, &materials, &enc_request)) {
        abort();
    }
    aws_cryptosdk_enc_materials_destroy(materials);

    aws_cryptosdk_cmm_release(cmm_a);
    aws_cryptosdk_cmm_release(cmm_b);

    aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);

    bool matched = aws_byte_buf_eq(&cache_id_a, &mock_materials_cache->last_cache_id);
    aws_byte_buf_clean_up(&cache_id_a);

    return matched;
}

static bool partitions_match_on_dec(
    const struct aws_byte_buf *partition_name_a, const struct aws_byte_buf *partition_name_b) {
    struct aws_cryptosdk_cmm *cmm_a = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, partition_name_a);
    struct aws_cryptosdk_cmm *cmm_b = aws_cryptosdk_caching_cmm_new(
        aws_default_allocator(), &mock_materials_cache->base, &mock_upstream_cmm->base, partition_name_b);

    struct aws_hash_table enc_ctx;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &enc_ctx));

    struct aws_cryptosdk_edk edk;
    edk.provider_id   = aws_byte_buf_from_c_str("provider_id");
    edk.provider_info = aws_byte_buf_from_c_str("provider_info");
    edk.ciphertext    = aws_byte_buf_from_c_str("enc_data_key");

    struct aws_cryptosdk_dec_request dec_request = { 0 };
    dec_request.alloc                            = aws_default_allocator();
    dec_request.alg                              = ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
    dec_request.enc_ctx                          = &enc_ctx;
    aws_array_list_init_static(&dec_request.encrypted_data_keys, &edk, 1, sizeof(edk));

    struct aws_cryptosdk_dec_materials *materials;
    if (aws_cryptosdk_cmm_decrypt_materials(cmm_a, &materials, &dec_request)) {
        abort();
    }
    aws_cryptosdk_dec_materials_destroy(materials);

    struct aws_byte_buf cache_id_a = mock_materials_cache->last_cache_id;
    // Prevent the cache ID from being freed on the next call
    mock_materials_cache->last_cache_id = aws_byte_buf_from_c_str("");

    if (aws_cryptosdk_cmm_decrypt_materials(cmm_b, &materials, &dec_request)) {
        abort();
    }
    aws_cryptosdk_dec_materials_destroy(materials);

    aws_cryptosdk_cmm_release(cmm_a);
    aws_cryptosdk_cmm_release(cmm_b);

    aws_cryptosdk_enc_ctx_clean_up(&enc_ctx);

    bool matched = aws_byte_buf_eq(&cache_id_a, &mock_materials_cache->last_cache_id);
    aws_byte_buf_clean_up(&cache_id_a);

    return matched;
}

static int same_partition_id_cache_ids_match() {
    setup_mocks();
    struct aws_byte_buf partition_id = aws_byte_buf_from_c_str("partition 1");

    TEST_ASSERT(partitions_match_on_enc(&partition_id, &partition_id));
    TEST_ASSERT(partitions_match_on_dec(&partition_id, &partition_id));

    teardown();

    return 0;
}

static int static_and_null_partition_id_dont_match() {
    setup_mocks();
    struct aws_byte_buf partition_id = aws_byte_buf_from_c_str("partition 1");

    TEST_ASSERT(!partitions_match_on_enc(&partition_id, NULL));
    TEST_ASSERT(!partitions_match_on_dec(&partition_id, NULL));

    teardown();

    return 0;
}

static int two_null_partition_ids_dont_match() {
    setup_mocks();

    TEST_ASSERT(!partitions_match_on_enc(NULL, NULL));
    TEST_ASSERT(!partitions_match_on_dec(NULL, NULL));

    teardown();

    return 0;
}

static int two_different_static_partition_ids_dont_match() {
    setup_mocks();
    struct aws_byte_buf p1 = aws_byte_buf_from_c_str("partition 1");
    struct aws_byte_buf p2 = aws_byte_buf_from_c_str("partition 2");

    TEST_ASSERT(!partitions_match_on_enc(&p1, &p2));
    TEST_ASSERT(!partitions_match_on_dec(&p1, &p2));

    teardown();

    return 0;
}

static void setup_mocks() {
    mock_materials_cache = mock_materials_cache_new(aws_default_allocator());
    mock_upstream_cmm    = mock_upstream_cmm_new(aws_default_allocator());

    if (!mock_materials_cache || !mock_upstream_cmm) abort();

    materials_cache = &mock_materials_cache->base;
    cmm             = &mock_upstream_cmm->base;
}

static void release_mocks() {
    // Check for reference leaks on teardown
    if (materials_cache && mock_materials_cache->entry_refcount != 0) {
        fprintf(
            stderr, "\nReference leak: %zu material entry references remain\n", mock_materials_cache->entry_refcount);
        abort();
    }

    aws_cryptosdk_materials_cache_release(materials_cache);
    aws_cryptosdk_cmm_release(cmm);

    materials_cache = NULL;
    cmm             = NULL;
}

static void teardown() {
    release_mocks();

    mock_materials_cache = NULL;
    mock_upstream_cmm    = NULL;
}

static int process_loop(
    struct aws_allocator *alloc,
    uint8_t **output_buf,
    size_t *output_len,
    struct aws_cryptosdk_session *session,
    const uint8_t *const input_buf,
    const size_t input_len) {
    size_t total_input_read = 0;
    size_t input_window     = 1;

    size_t output_size          = 1;
    *output_buf                 = aws_mem_acquire(alloc, output_size);
    size_t total_output_written = 0;
    size_t output_needed        = 1;
    bool set_message_size       = 1;

    /* The entire input is already in the input buffer and we just expand the window into it as needed.
     * The entire output will eventually be put into a single buffer. This is not a realistic streaming
     * use case as we cannot handle more data than fits in memory, but it keeps things simple for testing.
     */
    while (1) {
        size_t input_read, output_written;
        TEST_ASSERT_SUCCESS(aws_cryptosdk_session_process(
            session,
            *output_buf + total_output_written,
            output_size - total_output_written,
            &output_written,
            input_buf + total_input_read,
            input_window,
            &input_read));

        total_output_written += output_written;
        total_input_read += input_read;

        if (total_input_read == input_len && set_message_size) {
            TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, 100));
            set_message_size = 0;
        }

        if (aws_cryptosdk_session_is_done(session)) break;

        aws_cryptosdk_session_estimate_buf(session, &output_needed, &input_window);

        size_t output_size_needed = output_needed + total_output_written;
        if (output_size < output_size_needed) {
            TEST_ASSERT_SUCCESS(aws_mem_realloc(alloc, (void **)output_buf, output_size, output_size_needed));
            output_size = output_size_needed;
        }
    }
    *output_len = total_output_written;
    return 0;
}

static int set_message_bound_with_caching_cmm() {
    struct aws_allocator *alloc                 = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr            = NULL;
    struct aws_cryptosdk_cmm *default_cmm       = NULL;
    struct aws_cryptosdk_materials_cache *cache = NULL;
    struct aws_cryptosdk_cmm *caching_cmm       = NULL;
    struct aws_cryptosdk_session *session       = NULL;

    size_t plaintext_len     = 100;
    uint8_t *plaintext_buf_1 = aws_mem_acquire(alloc, plaintext_len);
    uint8_t *plaintext_buf_2 = aws_mem_acquire(alloc, plaintext_len);
    size_t ciphertext_len;
    uint8_t *ciphertext_buf_1;
    uint8_t *ciphertext_buf_2;
    size_t pt_consumed, ct_consumed;

    kr = aws_cryptosdk_zero_keyring_new(alloc);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    default_cmm = aws_cryptosdk_default_cmm_new(alloc, kr);
    TEST_ASSERT_ADDR_NOT_NULL(default_cmm);

    cache = aws_cryptosdk_materials_cache_local_new(alloc, 8);
    TEST_ASSERT_ADDR_NOT_NULL(cache);

    caching_cmm = aws_cryptosdk_caching_cmm_new(alloc, cache, default_cmm, NULL);
    TEST_ASSERT_ADDR_NOT_NULL(caching_cmm);

    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_cmm_release(default_cmm);

    session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_ENCRYPT, caching_cmm);
    TEST_ASSERT_ADDR_NOT_NULL(session);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_frame_size(session, 50));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_bound(session, 200));

    TEST_ASSERT_INT_EQ(0, aws_cryptosdk_materials_cache_entry_count(cache));
    TEST_ASSERT_ADDR_NOT_NULL(plaintext_buf_1);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_genrandom(plaintext_buf_1, plaintext_len));
    TEST_ASSERT_SUCCESS(
        process_loop(alloc, &ciphertext_buf_1, &ciphertext_len, session, plaintext_buf_1, plaintext_len));
    // asserting that there is a cache miss
    TEST_ASSERT_INT_EQ(1, aws_cryptosdk_materials_cache_entry_count(cache));

    TEST_ASSERT_ADDR_NOT_NULL(plaintext_buf_2);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_genrandom(plaintext_buf_2, plaintext_len));
    TEST_ASSERT_SUCCESS(
        process_loop(alloc, &ciphertext_buf_2, &ciphertext_len, session, plaintext_buf_2, plaintext_len));
    // asserting that there is a cache hit
    TEST_ASSERT_INT_EQ(1, aws_cryptosdk_materials_cache_entry_count(cache));

    aws_mem_release(alloc, plaintext_buf_1);
    aws_mem_release(alloc, plaintext_buf_2);
    aws_mem_release(alloc, ciphertext_buf_1);
    aws_mem_release(alloc, ciphertext_buf_2);
    aws_cryptosdk_materials_cache_release(cache);
    aws_cryptosdk_cmm_release(caching_cmm);
    aws_cryptosdk_session_destroy(session);

    return 0;
}

static int message_bound_error_code() {
    setup_mocks();
    size_t message_bound_size = 128;
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_bound(session, message_bound_size));
    /* Since we are setting the message_size value to be greater that the message_bound value set
    we expect a AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED error thrown. */
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED, aws_cryptosdk_session_set_message_size(session, 2 * message_bound_size));
    teardown();
    aws_cryptosdk_session_destroy(session);
    return 0;
}

#define TEST_CASE(name) \
    { "caching_cmm", #name, name }
struct test_case caching_cmm_test_cases[] = { TEST_CASE(create_destroy),
                                              TEST_CASE(enc_cache_miss),
                                              TEST_CASE(enc_cache_unique_ids),
                                              TEST_CASE(enc_cache_id_test_vecs),
                                              TEST_CASE(enc_cache_hit),
                                              TEST_CASE(limits_test),
                                              TEST_CASE(dec_cache_id_test_vecs),
                                              TEST_CASE(dec_materials),
                                              TEST_CASE(cache_miss_failed_put),
                                              TEST_CASE(same_partition_id_cache_ids_match),
                                              TEST_CASE(static_and_null_partition_id_dont_match),
                                              TEST_CASE(two_null_partition_ids_dont_match),
                                              TEST_CASE(two_different_static_partition_ids_dont_match),
                                              TEST_CASE(set_message_bound_with_caching_cmm),
                                              TEST_CASE(message_bound_error_code),
                                              { NULL } };

// TEST TODO: Threadstorm
