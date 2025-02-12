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

/*
 * This test is fairly slow, and for best coverage should not run at the same time
 * as other threads (we want it to contend with itself heavily, instead of getting a
 * fraction of a core and running effectively single-threaded).
 *
 * As such it's not part of the main test suite run by ctest, but is instead a separate
 * target executed during CI.
 */

// TODO: Make TTL expiry happen every once in a while

#include <aws/cryptosdk/cache.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/cipher.h>

#include <aws/common/thread.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <aws/common/mutex.h>
#include <aws/common/thread.h>

#include "cache_test_lib.h"
#include "testutil.h"

// Number of total distinct cache IDs we'll be working with
#define N_ENC_ENTRIES 50
#define N_DEC_ENTRIES 50
#define N_ENTRIES_TOTAL (N_ENC_ENTRIES + N_DEC_ENTRIES)

// Cache size. This should be smaller than N_ENTRIES_TOTAL in order to test LRU
#define CACHE_SIZE 80

// Probability that an entry is explicitly invalidated
#define P_INVALIDATE 0.0001

// Probability that a new TTL is set on cache hit
#define P_UPDATE_TTL 0.0001

// Probability that a TTL is set on initial insertion of an entry
#define P_INSERT_TTL 0.5

// Thread count
#define THREAD_COUNT 16

// Total running time, in milliseconds
#define RUN_TIME_MS 60000

static struct aws_cryptosdk_materials_cache *materials_cache;
static struct aws_atomic_var stop_flag;

static struct aws_cryptosdk_enc_materials *expected_enc_mats[N_ENC_ENTRIES];
static struct aws_cryptosdk_dec_materials *expected_dec_mats[N_DEC_ENTRIES];

// Avoid contention on the RNG state by using a custom linear congruential PRNG.
// We don't need anything particularly fancy or good, we're just looking to generate
// a random-ish access pattern without spending a lot of time on strong randomness.
struct rand_state {
    uint32_t state;
};

// MINSTD parameters
#define RNG_MODULUS UINT32_MAX  // 2^31 - 1
#define RNG_GENERATOR 16807
#define RNG_MAX (RNG_MODULUS - 1)

static unsigned long threadid_get_callback() {
    return (unsigned long)aws_thread_current_thread_id();
}

static struct aws_mutex *mutex_array = NULL;

static void lock_callback(int mode, int n, const char *file, int line) {
    int rv;
    if (mode & CRYPTO_LOCK) {
        rv = aws_mutex_lock(&mutex_array[n]);
    } else {
        rv = aws_mutex_unlock(&mutex_array[n]);
    }

    if (rv) {
        abort();
    }
}

static void libcrypto_init() {
    /* None of this is needed in openssl 1.1.0, but we still have to build on older versions... */
    ERR_load_crypto_strings();

    size_t num_locks = CRYPTO_num_locks();
    mutex_array      = aws_mem_acquire(aws_default_allocator(), sizeof(struct aws_mutex) * num_locks);

    for (size_t i = 0; i < num_locks; i++) {
        if (aws_mutex_init(&mutex_array[i])) {
            abort();
        }
    }

    CRYPTO_set_id_callback(threadid_get_callback);
    CRYPTO_set_locking_callback(lock_callback);
}

static uint32_t get_random(struct rand_state *state) {
    uint32_t val = state->state;

    uint64_t tmp = state->state;
    tmp *= RNG_GENERATOR;
    state->state = tmp % RNG_MODULUS;

    return val;
}

static void init_random(struct rand_state *state) {
    do {
        aws_cryptosdk_genrandom((uint8_t *)&state->state, sizeof(state->state));
    } while (state->state >= RNG_MODULUS || !state->state);
}

static struct aws_cryptosdk_materials_cache_entry *do_enc_operation(
    uint32_t entry_id, struct aws_hash_table *empty_table) {
    char buf[256];
    struct aws_byte_buf cache_id = aws_byte_buf_from_array((uint8_t *)buf, sizeof(buf));
    cache_id.len                 = sprintf(buf, "ENC ENTRY %u", (unsigned int)entry_id);

    struct aws_cryptosdk_materials_cache_entry *entry;
    bool is_encrypt;
    if (aws_cryptosdk_materials_cache_find_entry(materials_cache, &entry, &is_encrypt, &cache_id)) {
        abort();
    }
    if (entry && !is_encrypt) {
        abort();
    }

    struct aws_cryptosdk_enc_materials *materials;

    if (entry) {
        if (aws_cryptosdk_materials_cache_get_enc_materials(
                materials_cache, aws_default_allocator(), &materials, empty_table, entry)) {
            // Could have been a race with an invalidation, so ignore
        } else {
            if (!materials_eq(expected_enc_mats[entry_id], materials)) {
                abort();
            }

            aws_cryptosdk_enc_materials_destroy(materials);
        }
    } else {
        struct aws_cryptosdk_cache_usage_stats initial_usage = { 0 };
        aws_cryptosdk_materials_cache_put_entry_for_encrypt(
            materials_cache, &entry, expected_enc_mats[entry_id], initial_usage, empty_table, &cache_id);

        if (!entry) {
            abort();
        }
    }

    return entry;
}

static struct aws_cryptosdk_materials_cache_entry *do_dec_operation(
    uint32_t entry_id, struct aws_hash_table *empty_table) {
    char buf[256];
    struct aws_byte_buf cache_id = aws_byte_buf_from_array((uint8_t *)buf, sizeof(buf));
    cache_id.len                 = sprintf(buf, "DEC ENTRY %u", (unsigned int)entry_id);

    struct aws_cryptosdk_materials_cache_entry *entry;
    bool is_encrypt;

    if (aws_cryptosdk_materials_cache_find_entry(materials_cache, &entry, &is_encrypt, &cache_id)) {
        abort();
    }

    if (entry && is_encrypt) {
        abort();
    }

    if (entry) {
        struct aws_cryptosdk_dec_materials *materials;
        if (aws_cryptosdk_materials_cache_get_dec_materials(
                materials_cache, aws_default_allocator(), &materials, entry)) {
            // Could be a race with invalidate, ignore
        } else {
            if (!dec_materials_eq(materials, expected_dec_mats[entry_id])) {
                abort();
            }
            aws_cryptosdk_dec_materials_destroy(materials);
        }
    } else {
        aws_cryptosdk_materials_cache_put_entry_for_decrypt(
            materials_cache, &entry, expected_dec_mats[entry_id], &cache_id);

        if (!entry) {
            abort();
        }
    }

    return entry;
}

static void do_one_operation(struct rand_state *state, struct aws_hash_table *empty_table) {
    // Yes, I know, this isn't uniformly distributed.
    uint32_t entry_id = get_random(state) % N_ENTRIES_TOTAL;

#define P_INT_INVALIDATE (RNG_MAX * P_INVALIDATE)
#define P_INT_UPDATE_TTL (P_INT_INVALIDATE + (RNG_MAX * P_INVALIDATE))

    uint32_t op_probability = get_random(state);

    struct aws_cryptosdk_materials_cache_entry *entry;

    if (entry_id < N_ENC_ENTRIES) {
        entry = do_enc_operation(entry_id, empty_table);
    } else {
        entry = do_dec_operation(entry_id - N_ENC_ENTRIES, empty_table);
    }

    if (op_probability < P_INT_INVALIDATE) {
        aws_cryptosdk_materials_cache_entry_release(materials_cache, entry, true);
    } else {
        if (op_probability < P_INT_UPDATE_TTL) {
            // This might be above or below any prior TTL value
            uint64_t new_expiry = ((uint64_t)get_random(state) << 31) | get_random(state);
            aws_cryptosdk_materials_cache_entry_ttl_hint(materials_cache, entry, new_expiry);
        }

        aws_cryptosdk_materials_cache_entry_release(materials_cache, entry, false);
    }

    aws_hash_table_clear(empty_table);
}

static void thread_fn(void *ignored) {
    (void)ignored;

    struct rand_state state;
    struct aws_hash_table empty_table;

    init_random(&state);
    aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &empty_table);

    while (!aws_atomic_load_int_explicit(&stop_flag, aws_memory_order_relaxed)) {
        do_one_operation(&state, &empty_table);
    }

    aws_cryptosdk_enc_ctx_clean_up(&empty_table);
}

static void setup() {
    materials_cache = aws_cryptosdk_materials_cache_local_new(aws_default_allocator(), CACHE_SIZE);

    for (int i = 0; i < N_ENC_ENTRIES; i++) {
        gen_enc_materials(aws_default_allocator(), &expected_enc_mats[i], i, ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256, 1);
    }

    for (int i = 0; i < N_DEC_ENTRIES; i++) {
        expected_dec_mats[i] =
            aws_cryptosdk_dec_materials_new(aws_default_allocator(), ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256);

        expected_dec_mats[i]->signctx = NULL;
        struct aws_byte_buf *data_key = &expected_dec_mats[i]->unencrypted_data_key;
        if (aws_byte_buf_init(data_key, aws_default_allocator(), 16)) {
            abort();
        }
        memset(data_key->buffer, 0xAA, data_key->capacity);
        memcpy(data_key->buffer, &i, sizeof(i));
        data_key->len = data_key->capacity;
    }

    aws_atomic_init_int(&stop_flag, 0);
}

static void teardown() {
    aws_cryptosdk_materials_cache_release(materials_cache);

    for (int i = 0; i < N_ENC_ENTRIES; i++) {
        aws_cryptosdk_enc_materials_destroy(expected_enc_mats[i]);
        expected_enc_mats[i] = NULL;
    }

    for (int i = 0; i < N_DEC_ENTRIES; i++) {
        aws_cryptosdk_dec_materials_destroy(expected_dec_mats[i]);
        expected_dec_mats[i] = NULL;
    }
}

int main() {
    libcrypto_init();

    setup();

    struct aws_thread threads[THREAD_COUNT];
    struct aws_thread_options options = *aws_default_thread_options();

    for (int i = 0; i < THREAD_COUNT; i++) {
        aws_thread_init(&threads[i], aws_default_allocator());
        aws_thread_launch(&threads[i], thread_fn, NULL, &options);
    }

    aws_thread_current_sleep(RUN_TIME_MS * (1000LLU * 1000LLU));

    aws_atomic_store_int(&stop_flag, 1);

    for (int i = 0; i < THREAD_COUNT; i++) {
        aws_thread_join(&threads[i]);
        aws_thread_clean_up(&threads[i]);
    }

    teardown();

    return 0;
}
