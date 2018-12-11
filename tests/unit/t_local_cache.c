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

#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/common/byte_buf.h>
#include "testing.h"
#include "testutil.h"
#include "cache_test_lib.h"

static uint64_t now = 10000;

/* Exposed for unit tests only */
void aws_cryptosdk_local_cache_set_clock(
    struct aws_cryptosdk_mat_cache *generic_cache,
    int (*clock_get_ticks)(uint64_t *timestamp)
);

static int test_clock(uint64_t *timestamp) {
    *timestamp = now;
    return AWS_OP_SUCCESS;
}

static int test_clock_broken(uint64_t *timestamp) {
    (void)timestamp;

    return aws_raise_error(AWS_ERROR_UNKNOWN);
}

static int create_destroy() {
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(aws_default_allocator(), 16);

    aws_cryptosdk_mat_cache_release(cache);

    return 0;
}

static int single_put() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(alloc, 16);
    struct aws_cryptosdk_encryption_materials *enc_mat_1, *enc_mat_2;
    struct aws_cryptosdk_mat_cache_entry *entry = NULL;
    struct aws_hash_table enc_context_1, enc_context_2;
    struct aws_byte_buf cache_id;
    struct aws_cryptosdk_cache_usage_stats stats_1, stats_2;
    bool is_encrypt = false;

    stats_1.bytes_encrypted = 1234;
    stats_1.messages_encrypted = 4567;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(alloc, &enc_context_1));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(alloc, &enc_context_2));
    TEST_ASSERT_SUCCESS(aws_hash_table_put(&enc_context_1,
        aws_string_new_from_c_str(alloc, "foo"),
        aws_string_new_from_c_str(alloc, "bar"),
        NULL
    ));

    gen_enc_materials(alloc, &enc_mat_1, 1, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, 3);
    byte_buf_printf(&cache_id, alloc, "Cache ID 1");

    aws_cryptosdk_mat_cache_put_entry_for_encrypt(
        cache,
        &entry,
        enc_mat_1,
        stats_1,
        &enc_context_1,
        &cache_id
    );

    TEST_ASSERT_ADDR_NOT_NULL(entry);
    aws_cryptosdk_mat_cache_entry_release(cache, entry, false);

    stats_2.bytes_encrypted = 90000;
    stats_2.messages_encrypted = 80000;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_mat_cache_find_entry(cache, &entry, &is_encrypt, &cache_id));
    TEST_ASSERT_ADDR_NOT_NULL(entry);
    TEST_ASSERT(is_encrypt);
    
    TEST_ASSERT_SUCCESS(aws_cryptosdk_mat_cache_update_usage_stats(cache, entry, &stats_2));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_mat_cache_get_encryption_materials(cache, alloc, &enc_mat_2, &enc_context_2, entry));

    struct aws_cryptosdk_decryption_materials *dec_materials = (struct aws_cryptosdk_decryption_materials *)0xAA;
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_mat_cache_get_decryption_materials(cache, alloc, &dec_materials, entry)
    );
    TEST_ASSERT_ADDR_NULL(dec_materials);

    TEST_ASSERT_ADDR_NOT_NULL(enc_mat_2);

    TEST_ASSERT_INT_EQ(stats_2.bytes_encrypted, 91234);
    TEST_ASSERT_INT_EQ(stats_2.messages_encrypted, 84567);

    TEST_ASSERT(materials_eq(enc_mat_1, enc_mat_2));
    TEST_ASSERT(aws_hash_table_eq(&enc_context_1, &enc_context_2, aws_string_eq));

    aws_cryptosdk_mat_cache_entry_release(cache, entry, true);
    aws_cryptosdk_encryption_materials_destroy(enc_mat_2);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_mat_cache_find_entry(cache, &entry, &is_encrypt, &cache_id));

    TEST_ASSERT_ADDR_NULL(entry);

    aws_byte_buf_clean_up(&cache_id);
    aws_cryptosdk_encryption_materials_destroy(enc_mat_1);
    aws_cryptosdk_enc_context_clean_up(&enc_context_1);
    aws_cryptosdk_enc_context_clean_up(&enc_context_2);
    aws_cryptosdk_mat_cache_release(cache);

    return 0;
}

static int entry_refcount() {
    /*
     * In this test, we will keep an entry reference alive and manipulate it after invalidation.
     * This is mostly dependent on valgrind to catch memory errors.
     */
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(alloc, 16);
    struct aws_cryptosdk_encryption_materials *enc_mat_1;
    struct aws_cryptosdk_mat_cache_entry *entry_1 = NULL, *entry_2 = NULL;
    struct aws_hash_table enc_context_1, enc_context_2;
    struct aws_byte_buf cache_id;
    struct aws_cryptosdk_cache_usage_stats stats_1 = {0}, stats_2 = {0};

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(alloc, &enc_context_1));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(alloc, &enc_context_2));
    TEST_ASSERT_SUCCESS(aws_hash_table_put(&enc_context_1,
        aws_string_new_from_c_str(alloc, "foo"),
        aws_string_new_from_c_str(alloc, "bar"),
        NULL
    ));

    gen_enc_materials(alloc, &enc_mat_1, 1, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, 3);
    byte_buf_printf(&cache_id, alloc, "Cache ID 1");

    aws_cryptosdk_mat_cache_put_entry_for_encrypt(
        cache,
        &entry_1,
        enc_mat_1,
        stats_1,
        &enc_context_1,
        &cache_id
    );
    /* Free enc_mat_1 and the context hash table immediately to prove that the cache isn't using them */
    aws_cryptosdk_encryption_materials_destroy(enc_mat_1);
    aws_cryptosdk_enc_context_clean_up(&enc_context_1);

    TEST_ASSERT_ADDR_NOT_NULL(entry_1);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_mat_cache_find_entry(
        cache, &entry_2, NULL, &cache_id
    ));

    TEST_ASSERT_ADDR_NOT_NULL(entry_2);

    aws_cryptosdk_mat_cache_entry_release(cache, entry_2, true);

    /* It should be safe to manipulate entry_1 still */
    TEST_ASSERT_INT_NE(UINT64_MAX, aws_cryptosdk_mat_cache_entry_get_creation_time(cache, entry_1));
    aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry_1, aws_cryptosdk_mat_cache_entry_get_creation_time(cache, entry_1) + 1000000000ULL);

    /* Releasing with invalidate=true should be safe */
    aws_cryptosdk_mat_cache_entry_release(cache, entry_2, true);

    aws_byte_buf_clean_up(&cache_id);
    aws_cryptosdk_enc_context_clean_up(&enc_context_2);
    aws_cryptosdk_mat_cache_release(cache);

    return 0;
}

static int setup_enc_params(int index, struct aws_cryptosdk_encryption_materials **enc_mat, struct aws_hash_table *enc_context, struct aws_byte_buf *cache_id) {
    AWS_STATIC_STRING_FROM_LITERAL(key, "entry index");
    char tmpbuf[256];
    struct aws_string *enc_context_val;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(aws_default_allocator(), enc_context));
    sprintf(tmpbuf, "%d", index);

    enc_context_val = aws_string_new_from_c_str(aws_default_allocator(), tmpbuf);
    if (!enc_context_val) abort();
    TEST_ASSERT_SUCCESS(aws_hash_table_put(enc_context, key, enc_context_val, NULL));

    gen_enc_materials(aws_default_allocator(), enc_mat, index, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, 1 + (index % 4));
    byte_buf_printf(cache_id, aws_default_allocator(), "ID %d", index);

    return 0;
}

static void insert_enc_entry(struct aws_cryptosdk_mat_cache *cache, int index, struct aws_cryptosdk_mat_cache_entry **p_entry) {
    struct aws_cryptosdk_encryption_materials *enc_mat;
    struct aws_hash_table enc_context;
    struct aws_byte_buf cache_id;

    struct aws_cryptosdk_mat_cache_entry *entry;
    struct aws_cryptosdk_cache_usage_stats stats = {index, index};

    if (setup_enc_params(index, &enc_mat, &enc_context, &cache_id)) abort();

    aws_cryptosdk_mat_cache_put_entry_for_encrypt(cache, &entry, enc_mat, stats, &enc_context, &cache_id);
    if (!entry) abort();

    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_byte_buf_clean_up(&cache_id);
    aws_cryptosdk_enc_context_clean_up(&enc_context);

    if (p_entry) {
        *p_entry = entry;
    } else {
        aws_cryptosdk_mat_cache_entry_release(cache, entry, false);
    }
}

static int check_enc_entry(
    struct aws_cryptosdk_mat_cache *cache,
    int index,
    bool expected_present,
    bool invalidate,
    struct aws_cryptosdk_mat_cache_entry **p_entry
) {
    struct aws_cryptosdk_encryption_materials *enc_mat, *cached_materials = NULL;
    struct aws_hash_table enc_context, cached_context;
    struct aws_byte_buf cache_id;

    struct aws_cryptosdk_mat_cache_entry *entry;
    struct aws_cryptosdk_cache_usage_stats stats = {0, 0};

    if (setup_enc_params(index, &enc_mat, &enc_context, &cache_id)) return 1;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(aws_default_allocator(), &cached_context));

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_mat_cache_find_entry(cache, &entry, NULL, &cache_id)
    );

    if (!expected_present) {
        if (entry) {
            fprintf(stderr, "\nUnexpected entry for material #%d\n", index);
        }
        TEST_ASSERT_ADDR_NULL(entry);
    } else {
        if (!entry) {
            fprintf(stderr, "\nMissing entry for material #%d\n", index);
        }

        TEST_ASSERT_SUCCESS(
            aws_cryptosdk_mat_cache_get_encryption_materials(
                cache, aws_default_allocator(), &cached_materials, &cached_context, entry
            )
        );

        TEST_ASSERT_SUCCESS(
            aws_cryptosdk_mat_cache_update_usage_stats(cache, entry, &stats)   
        );

        TEST_ASSERT_ADDR_NOT_NULL(cached_materials);
        TEST_ASSERT_ADDR_NOT_NULL(entry);

        TEST_ASSERT(materials_eq(enc_mat, cached_materials));
        TEST_ASSERT(aws_hash_table_eq(&enc_context, &cached_context, aws_string_eq));
        TEST_ASSERT_INT_EQ(index, stats.bytes_encrypted);
        TEST_ASSERT_INT_EQ(index, stats.messages_encrypted);
    }

    aws_cryptosdk_mat_cache_entry_release(cache, entry, invalidate);
    aws_cryptosdk_encryption_materials_destroy(enc_mat);
    aws_cryptosdk_encryption_materials_destroy(cached_materials);
    aws_byte_buf_clean_up(&cache_id);
    aws_cryptosdk_enc_context_clean_up(&enc_context);
    aws_cryptosdk_enc_context_clean_up(&cached_context);

    return 0;
}

static int test_lru() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(alloc, 16);

    for (int i = 0; i <= 16; i++) {
        insert_enc_entry(cache, i, NULL);
    }

    /* Entry 0 should be LRU-evicted */
    if (check_enc_entry(cache, 0, false, false, NULL)) {
        return 1;
    }

    for (int i = 1; i <= 16; i++) {
        /* All other entries should be present */
        if (check_enc_entry(cache, i, true, false, NULL)) return 1;
    }

    /* Make entry 5 the least recently used */
    for (int i = 1; i <= 16; i++) {
        if (i != 5 && check_enc_entry(cache, i, true, false, NULL)) return 1;
    }

    insert_enc_entry(cache, 17, NULL);

    /* Verify that entry 5 is gone now. While we're at it, drop entry 17 */
    for (int i = 1; i <= 17; i++) {
        if (check_enc_entry(cache, i, i != 5, i == 17, NULL)) return 1;
    }

    /* Now we'll insert 5 again; we shouldn't drop anything, after freeing space by dropping 17 */
    insert_enc_entry(cache, 5, NULL);
    for (int i = 1; i <= 16; i++) {
        if (check_enc_entry(cache, i, true, false, NULL)) return 1;
    }

    aws_cryptosdk_mat_cache_release(cache);

    return 0;
}


static int test_ttl() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(alloc, 16);

    now = 10000;
    aws_cryptosdk_local_cache_set_clock(cache, test_clock);

    for (int i = 0; i < 16; i++) {
        struct aws_cryptosdk_mat_cache_entry *entry;
        insert_enc_entry(cache, i, &entry);

        if (i == 15) {
            /* Entry 15 will be MRU, but we'll have it expire soon */
            aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10010);
        } else if (i == 14) {
            /* Entry 14 will expire slightly later */
            aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10030);
            aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10011);
        } else if (i == 13) {
            /* Also test the case where the smaller ttl comes first */
            aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10012);
            aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10040);
        } else if (i == 12) {
            /* Entry 12 will be invalidated before expiration */
            aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10013);
        } else {
            /*
             * All other entries will be in the pqueue, but not expire.
             * This tests handling during cache teardown.
             */
            aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 20000);
        }

        aws_cryptosdk_mat_cache_entry_release(cache, entry, false);
    }

    now = 10010;

    /* Entry 15 should expire */
    insert_enc_entry(cache, 16, NULL);

    if (check_enc_entry(cache, 15, false, false, NULL)) return 1;

    for (int i = 0; i < 15; i++) {
        if (check_enc_entry(cache, i, true, false, NULL)) return 1;
    }

    now = 10011;
    /* Entry 14 should expire */
    if (check_enc_entry(cache, 14, false, false, NULL)) return 1;
    for (int i = 0; i < 14; i++) {
        if (check_enc_entry(cache, i, true, false, NULL)) return 1;
    }

    now = 10012;
    if (check_enc_entry(cache, 13, false, false, NULL)) return 1;
    for (int i = 0; i < 13; i++) {
        if (check_enc_entry(cache, i, true, false, NULL)) return 1;
    }

    /* Invalidate 12 before expiration. */
    if (check_enc_entry(cache, 12, true, true, NULL)) return 1;
    now = 10013;

    /*
     * Now insert more entries. We're testing to make sure the pqueue entry for 12 is
     * gone after normal invalidation.
     */
    for (int i = 20; i < 25; i++) {
        insert_enc_entry(cache, i, NULL);
    }

    aws_cryptosdk_mat_cache_release(cache);

    return 0;
}

static int overwrite_enc_entry() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(alloc, 16);
    struct aws_cryptosdk_mat_cache_entry *entry;

    now = 10000;
    aws_cryptosdk_local_cache_set_clock(cache, test_clock);

    insert_enc_entry(cache, 1, &entry);
    aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10100);

    insert_enc_entry(cache, 1, NULL);
    aws_cryptosdk_mat_cache_entry_release(cache, entry, false);

    check_enc_entry(cache, 1, true, false, NULL);

    now = 10100;
    /* The cache shouldn't expire the entry we overwrote */
    insert_enc_entry(cache, 2, NULL);
    insert_enc_entry(cache, 2, NULL);

    aws_cryptosdk_mat_cache_release(cache);

    return 0;
}

static int clear_cache() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(alloc, 16);
    struct aws_cryptosdk_mat_cache_entry *entry;

    now = 10000;
    aws_cryptosdk_local_cache_set_clock(cache, test_clock);

    insert_enc_entry(cache, 1, &entry);
    aws_cryptosdk_mat_cache_entry_ttl_hint(cache, entry, 10100);
    aws_cryptosdk_mat_cache_entry_release(cache, entry, false);

    insert_enc_entry(cache, 2, NULL);
    insert_enc_entry(cache, 3, NULL);

    aws_cryptosdk_mat_cache_clear(cache);
    now = 10100;
    /* Should not trigger TTL expiry */
    insert_enc_entry(cache, 4, NULL);

    check_enc_entry(cache, 1, false, false, NULL);
    check_enc_entry(cache, 2, false, false, NULL);
    check_enc_entry(cache, 3, false, false, NULL);

    aws_cryptosdk_mat_cache_release(cache);

    return 0;
}

uint64_t hash_cache_id(const void *vp_buf);

static int hash_truncation() {
    uint8_t short_buf[] = { 0x01, 0x02 };
    struct aws_byte_buf bytebuf = aws_byte_buf_from_array(short_buf, sizeof(short_buf));

    TEST_ASSERT_INT_EQ(0x0102, hash_cache_id(&bytebuf));

    uint8_t long_buf[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    bytebuf = aws_byte_buf_from_array(long_buf, sizeof(long_buf));

    TEST_ASSERT_INT_EQ(0x0102030405060708ull, hash_cache_id(&bytebuf));

    return 0;
}

static int test_decrypt_entries() {
    struct aws_cryptosdk_mat_cache *cache = aws_cryptosdk_mat_cache_local_new(aws_default_allocator(), 16);
    struct aws_byte_buf cache_id = aws_byte_buf_from_c_str("Hello, world!");
    struct aws_byte_buf expected_key = aws_byte_buf_from_c_str("THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE");
    struct aws_cryptosdk_decryption_materials *dec_mat_in = aws_cryptosdk_decryption_materials_new(aws_default_allocator(), AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384);
    AWS_STATIC_STRING_FROM_LITERAL(pubkey, "AoZ0mPKrKqcCyWlF47FYUrk4as696N4WUmv+54kp58hBiGJ22Fm+g4esiICWcOrgfQ==");

    TEST_ASSERT_SUCCESS(aws_byte_buf_init_copy(&dec_mat_in->unencrypted_data_key, aws_default_allocator(), &expected_key));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_start(&dec_mat_in->signctx, aws_default_allocator(), pubkey, aws_cryptosdk_alg_props(dec_mat_in->alg)));

    struct aws_cryptosdk_mat_cache_entry *entry = NULL;
    aws_cryptosdk_mat_cache_put_entry_for_decrypt(
        cache, &entry, dec_mat_in, &cache_id
    );
    TEST_ASSERT_ADDR_NOT_NULL(entry);
    aws_cryptosdk_mat_cache_entry_release(cache, entry, false);

    struct aws_cryptosdk_decryption_materials *dec_mat_out = (struct aws_cryptosdk_decryption_materials *)0xAA;
    struct aws_cryptosdk_encryption_materials *enc_mat_out = (struct aws_cryptosdk_encryption_materials *)0xAA;
    struct aws_hash_table enc_context;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(aws_default_allocator(), &enc_context));

    bool is_encrypt = true;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_mat_cache_find_entry(
        cache, &entry, &is_encrypt, &cache_id
    ));
    TEST_ASSERT(!is_encrypt);
    TEST_ASSERT_ADDR_NOT_NULL(entry);
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_mat_cache_get_encryption_materials(
            cache, aws_default_allocator(), &enc_mat_out, &enc_context, entry
        )
    );
    TEST_ASSERT_ADDR_NULL(enc_mat_out);

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_mat_cache_get_decryption_materials(cache, aws_default_allocator(), &dec_mat_out, entry)
    );
    aws_cryptosdk_mat_cache_entry_release(cache, entry, true);

    TEST_ASSERT(aws_byte_buf_eq(&expected_key, &dec_mat_out->unencrypted_data_key));

    struct aws_string *pubkey_out;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_get_pubkey(dec_mat_out->signctx, aws_default_allocator(), &pubkey_out));
    TEST_ASSERT(aws_string_eq(pubkey_out, pubkey));
    TEST_ASSERT_INT_EQ(dec_mat_out->alg, dec_mat_in->alg);

    TEST_ASSERT_ADDR_NE(dec_mat_out->unencrypted_data_key.buffer, dec_mat_in->unencrypted_data_key.buffer);
    TEST_ASSERT_ADDR_NE(dec_mat_out->signctx, dec_mat_in->signctx);

    aws_string_destroy(pubkey_out);
    aws_cryptosdk_decryption_materials_destroy(dec_mat_out);
    aws_cryptosdk_decryption_materials_destroy(dec_mat_in);
    aws_cryptosdk_mat_cache_release(cache);
    aws_cryptosdk_enc_context_clean_up(&enc_context);

    return 0;
}

#define TEST_CASE(name) { "local_cache", #name, name }
struct test_case local_cache_test_cases[] = {
    TEST_CASE(create_destroy),
    TEST_CASE(single_put),
    TEST_CASE(entry_refcount),
    TEST_CASE(test_lru),
    TEST_CASE(test_ttl),
    TEST_CASE(overwrite_enc_entry),
    TEST_CASE(clear_cache),
    TEST_CASE(hash_truncation),
    TEST_CASE(test_decrypt_entries),
    { NULL }
};
