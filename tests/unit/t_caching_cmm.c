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
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/default_cmm.h>

#include <aws/common/encoding.h>

#include <stdarg.h>

#include "testing.h"
#include "testutil.h"
#include "cache_test_lib.h"
#include "counting_keyring.h"

/*
 * Pointers to the underlying mocks set up by setup_mocks.
 */
static struct mock_mat_cache *mock_mat_cache;
static struct mock_upstream_cmm *mock_upstream_cmm;
/*
 * Typecasted pointers to the mocks. These pointers are considered
 * to hold a reference; to test that the caching CMM holds a reference,
 * call release_mocks(), which releases these and nulls them out.
 */
static struct aws_cryptosdk_mat_cache *mat_cache;
static struct aws_cryptosdk_cmm *cmm;

static void setup_mocks();
static void teardown();
static void release_mocks();

static int create_destroy() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(aws_default_allocator(), &mock_mat_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    aws_cryptosdk_cmm_release(cmm);
    teardown();

    return 0;
}

static int enc_cache_miss() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(aws_default_allocator(), &mock_mat_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    struct aws_hash_table req_context, expect_context;
    aws_cryptosdk_enc_context_init(aws_default_allocator(), &req_context);
    aws_cryptosdk_enc_context_init(aws_default_allocator(), &expect_context);

    struct aws_cryptosdk_encryption_request request;
    request.alloc = aws_default_allocator();
    request.requested_alg = 0;
    request.plaintext_size = 32768;

    struct aws_cryptosdk_encryption_materials *output, *expected;

    mock_upstream_cmm->n_edks = 5;
    mock_upstream_cmm->returned_alg = AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384;

    request.enc_context = &expect_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(&mock_upstream_cmm->base, &expected, &request));

    request.enc_context = &req_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(cmm, &output, &request));

    /* Materials should match those returned from the upstream */
    TEST_ASSERT(materials_eq(output, expected));
    TEST_ASSERT(aws_hash_table_eq(&req_context, &expect_context, aws_string_eq));
    /* The upstream CMM should see the original request */
    TEST_ASSERT_ADDR_EQ(mock_upstream_cmm->last_enc_request, &request);
    /* We should have inserted the result into the cache */
    TEST_ASSERT(materials_eq(output, mock_mat_cache->enc_materials));
    TEST_ASSERT(aws_hash_table_eq(&req_context, &mock_mat_cache->encryption_context, aws_string_eq));
    TEST_ASSERT_INT_EQ(request.plaintext_size, mock_mat_cache->usage_stats.bytes_encrypted);
    TEST_ASSERT_INT_EQ(1, mock_mat_cache->usage_stats.messages_encrypted);

    aws_cryptosdk_enc_context_clean_up(&req_context);
    aws_cryptosdk_enc_context_clean_up(&expect_context);
    aws_cryptosdk_encryption_materials_destroy(output);
    aws_cryptosdk_encryption_materials_destroy(expected);

    aws_cryptosdk_cmm_release(cmm);
    teardown();
}

static int enc_cache_hit() {
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(aws_default_allocator(), &mock_mat_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    struct aws_hash_table req_context, expect_context;
    aws_cryptosdk_enc_context_init(aws_default_allocator(), &req_context);
    aws_cryptosdk_enc_context_init(aws_default_allocator(), &expect_context);

    struct aws_cryptosdk_encryption_request request;
    request.alloc = aws_default_allocator();
    request.requested_alg = 0;
    request.plaintext_size = 32768;

    struct aws_cryptosdk_encryption_materials *output, *expected;

    mock_upstream_cmm->n_edks = 5;
    mock_upstream_cmm->returned_alg = AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384;

    request.enc_context = &expect_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(&mock_upstream_cmm->base, &expected, &request));

    /* Perform a cache miss to initialize things... */
    request.enc_context = &req_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(cmm, &output, &request));
    mock_mat_cache->usage_stats.bytes_encrypted = 42;
    mock_mat_cache->should_hit = true;
    
    struct aws_byte_buf cache_id_buf;
    TEST_ASSERT_SUCCESS(aws_byte_buf_init_copy(aws_default_allocator(), &cache_id_buf, &mock_mat_cache->last_cache_id));

    /* this should stay null after a hit */
    mock_upstream_cmm->last_enc_request = NULL;
    aws_hash_table_clear(&req_context);

    /* This should be a hit */
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(cmm, &output, &request));

    /* Materials should match those returned from the upstream */
    TEST_ASSERT(materials_eq(output, expected));
    TEST_ASSERT(aws_hash_table_eq(&req_context, &expect_context, aws_string_eq));

    /* The upstream CMM should not see the original request */
    TEST_ASSERT_ADDR_EQ(mock_upstream_cmm->last_enc_request, NULL);

    /* We should have updated the usage stats */
    TEST_ASSERT_INT_EQ(request.plaintext_size + 42, mock_mat_cache->usage_stats.bytes_encrypted);
    TEST_ASSERT_INT_EQ(2, mock_mat_cache->usage_stats.messages_encrypted);

    /* Same cache ID should have been seen */
    TEST_ASSERT(aws_byte_buf_eq(&cache_id_buf, &mock_mat_cache->last_cache_id));

    aws_cryptosdk_enc_context_clean_up(&req_context);
    aws_cryptosdk_enc_context_clean_up(&expect_context);
    aws_cryptosdk_encryption_materials_destroy(output);
    aws_cryptosdk_encryption_materials_destroy(expected);
    aws_byte_buf_clean_up(&cache_id_buf);

    aws_cryptosdk_cmm_release(cmm);
    teardown();
}

static int enc_cache_unique_ids() {
    struct aws_allocator *alloc = aws_default_allocator();
    setup_mocks();
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_caching_cmm_new(aws_default_allocator(), &mock_mat_cache->base, &mock_upstream_cmm->base, NULL);
    release_mocks();

    struct aws_hash_table req_context, output_context, seen_ids;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(aws_default_allocator(), &req_context));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(aws_default_allocator(), &output_context));
    TEST_ASSERT_SUCCESS(aws_hash_table_init(&seen_ids, aws_default_allocator(), 16, aws_hash_string, aws_string_eq, aws_string_destroy, NULL));

    struct aws_cryptosdk_encryption_request request;
    request.alloc = aws_default_allocator();
    request.requested_alg = 0;
    request.plaintext_size = 32768; 
    request.enc_context = &req_context;

    mock_upstream_cmm->n_edks = 1;
    mock_upstream_cmm->returned_alg = AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384;

#define ASSERT_UNIQUE_ID(is_unique) do { \
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_clone(aws_default_allocator(), &output_context, &req_context)); \
    if (request.requested_alg) mock_upstream_cmm->returned_alg = request.requested_alg; \
    struct aws_cryptosdk_encryption_materials *materials = NULL; \
    TEST_ASSERT_SUCCESS(aws_cryptosdk_cmm_generate_encryption_materials(cmm, &materials, &request)); \
    aws_cryptosdk_encryption_materials_destroy(materials); \
    struct aws_string *cache_id = aws_string_new_from_array(aws_default_allocator(), mock_mat_cache->last_cache_id.buffer, mock_mat_cache->last_cache_id.len); \
    int was_created; \
    TEST_ASSERT_SUCCESS(aws_hash_table_put(&seen_ids, cache_id, NULL, &was_created)); \
    TEST_ASSERT_INT_EQ(was_created, is_unique); \
} while (0)

    ASSERT_UNIQUE_ID(true);

    request.requested_alg = AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384;
    ASSERT_UNIQUE_ID(true);

    request.requested_alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE;
    ASSERT_UNIQUE_ID(true);

    // Changing the plaintext size should not change the cache ID
    request.plaintext_size = 65536;

    ASSERT_UNIQUE_ID(false);

    // Changing the context should change the cache ID
    TEST_ASSERT_SUCCESS(
        aws_hash_table_put(&req_context, aws_string_new_from_c_str(alloc, "foo"), aws_string_new_from_c_str(alloc, "bar"), NULL)
    );
    ASSERT_UNIQUE_ID(true);

    TEST_ASSERT_SUCCESS(
        aws_hash_table_put(&req_context, aws_string_new_from_c_str(alloc, "foo"), aws_string_new_from_c_str(alloc, "baz"), NULL)
    );
    ASSERT_UNIQUE_ID(true);

    aws_hash_table_clear(&req_context);
    // Hash keys are used in the cache ID computation, not just values
    TEST_ASSERT_SUCCESS(
        aws_hash_table_put(&req_context, aws_string_new_from_c_str(alloc, "foobar"), aws_string_new_from_c_str(alloc, "bar"), NULL)
    );
    ASSERT_UNIQUE_ID(true);

    // The cache ID calculation looks at multiple hash entries
    TEST_ASSERT_SUCCESS(
        aws_hash_table_put(&req_context, aws_string_new_from_c_str(alloc, "foo"), aws_string_new_from_c_str(alloc, "bar"), NULL)
    );
    ASSERT_UNIQUE_ID(true);

    aws_hash_table_clean_up(&seen_ids);
    aws_hash_table_clean_up(&output_context);
    aws_hash_table_clean_up(&req_context);

    aws_cryptosdk_cmm_release(cmm);

    teardown();

    return 0;
}

struct aws_string *prep_partition_id(struct aws_allocator *alloc, const struct aws_byte_buf *partition_id);
int hash_encrypt_request(struct aws_string *partition_id, struct aws_byte_buf *out, const struct aws_cryptosdk_encryption_request *req);

static int encrypt_id_vector(const char *expected_b64, const char *partition_name, enum aws_cryptosdk_alg_id requested_alg, /* k, v, k, v, NULL */ ...) {
    struct aws_byte_buf partition_name_buf = aws_byte_buf_from_c_str(partition_name);
    struct aws_string *partition_id = prep_partition_id(aws_default_allocator(), &partition_name_buf);
    TEST_ASSERT_ADDR_NOT_NULL(partition_id);

    struct aws_byte_buf expected_b64_buf, expected, actual;
    size_t expected_size;

    expected_b64_buf = aws_byte_buf_from_c_str(expected_b64);
    TEST_ASSERT_SUCCESS(aws_base64_compute_decoded_len(expected_b64, strlen(expected_b64), &expected_size));
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(aws_default_allocator(), &expected, expected_size));
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(aws_default_allocator(), &actual, expected_size));
    TEST_ASSERT_SUCCESS(aws_base64_decode(&expected_b64_buf, &expected));

    struct aws_cryptosdk_encryption_request request;
    struct aws_hash_table encryption_context;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(aws_default_allocator(), &encryption_context));

    request.alloc = aws_default_allocator();
    request.plaintext_size = 0;
    request.requested_alg = requested_alg;
    request.enc_context = &encryption_context;

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

    TEST_ASSERT_SUCCESS(hash_encrypt_request(partition_id, &actual, &request));

    TEST_ASSERT(aws_byte_buf_eq(&expected, &actual));

    aws_cryptosdk_enc_context_clean_up(&encryption_context);
    aws_byte_buf_clean_up(&expected);
    aws_byte_buf_clean_up(&actual);
    aws_string_destroy(partition_id);

    return 0;
}

static int enc_cache_id_test_vecs() {
    const char *partition_name = "c15b9079-6d0e-42b6-8784-5e804b025692";
    TEST_ASSERT(0 == encrypt_id_vector(
        "rkrFAso1YyPbOJbmwVMjrPw+wwLJT7xusn8tA8zMe9e3+OqbtfDueB7bvoKLU3fsmdUvZ6eMt7mBp1ThMMB25Q==",
        partition_name,
        0,
        NULL
    ));

    TEST_ASSERT(0 == encrypt_id_vector(
        "3icBIkLK4V3fVwbm3zSxUdUQV6ZvZYUOLl8buN36g6gDMqAkghcGryxX7QiVABkW1JhB6GRp5z+bzbiuciBcKQ==",
        partition_name,
        AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
        NULL
    ));

#define CONTEXT_FULL \
    "this", "is", "a", "non-empty", "encryption", "context", NULL

    TEST_ASSERT(0 == encrypt_id_vector(
        "IHiUHYOUVUEFTc3BcZPJDlsWct2Qy1A7JdfQl9sQoV/ILIbRpoz9q7RtGd/MlibaGl5ihE66cN8ygM8A5rtYbg==",
        partition_name,
        0,
        CONTEXT_FULL
    ));

    TEST_ASSERT(0 == encrypt_id_vector(
        "mRNK7qhTb/kJiiyGPgAevp0gwFRcET4KeeNYwZHhoEDvSUzQiDgl8Of+YRDaVzKxAqpNBgcAuFXde9JlaRRsmw==",
        partition_name,
        AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
        CONTEXT_FULL
    ));

    return 0;
}

static void setup_mocks() {
    mock_mat_cache = mock_mat_cache_new(aws_default_allocator());
    mock_upstream_cmm = mock_upstream_cmm_new(aws_default_allocator());

    if (!mock_mat_cache || !mock_upstream_cmm) abort();

    mat_cache = &mock_mat_cache->base;
    cmm = &mock_upstream_cmm->base;
}

static void release_mocks() {
    aws_cryptosdk_mat_cache_release(mat_cache);
    aws_cryptosdk_cmm_release(cmm);

    mat_cache = NULL;
    cmm = NULL;
}

static void teardown() {
    release_mocks();

    mock_mat_cache = NULL;
    mock_upstream_cmm = NULL;
}

#define TEST_CASE(name) { "caching_cmm", #name, name }
struct test_case caching_cmm_test_cases[] = {
    TEST_CASE(create_destroy),
    TEST_CASE(enc_cache_miss),
    TEST_CASE(enc_cache_unique_ids),
    TEST_CASE(enc_cache_id_test_vecs),
    TEST_CASE(enc_cache_hit),
    { NULL }
};