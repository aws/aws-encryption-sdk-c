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

#ifndef TESTUTIL_H
#define TESTUTIL_H

#include <stdint.h>
#include <stdio.h>
#include <aws/common/hash_table.h>
#include <aws/common/byte_buf.h>

#if defined(_MSC_VER) && !defined(AWS_ENCRYPTION_SDK_FORCE_STATIC) && defined(AWS_ENCRYPTION_SDK_SHARED)
#ifdef IN_TESTLIB_BUILD
#define TESTLIB_API __declspec(dllexport)
#else
#define TESTLIB_API __declspec(dllimport)
#endif
#else
#define TESTLIB_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Formats a string using printf format specifiers, and places it into buf, allocating space using alloc.
 * Aborts on allocation failure.
 */
TESTLIB_API
void byte_buf_printf(struct aws_byte_buf *buf, struct aws_allocator *alloc, const char *fmt, ...);

/* 
 * Loads a file from disk into a newly malloc'd buffer.
 * Returns 0 on success, 1 on failure (examine errno for details)
 */
TESTLIB_API
int test_loadfile(const char *filename, uint8_t **buf, size_t *datasize);

/*
 * Performs a human-readable hexdump of the given buffer
 */
TESTLIB_API
void hexdump(FILE *fd, const uint8_t *buf, size_t size);

/**
 * Creates and initializes with fixed strings an encryption context
 * Note: enc_context needs to be cleaned using aws_hash_table_clean_up
 * @param alloc Allocator for initializing the hash table
 * @param enc_context Output variable with an initialized hash_table
 * @return
 */
TESTLIB_API
int test_enc_context_init_and_fill(struct aws_allocator *alloc,
                                   struct aws_hash_table *enc_context);

/**
 * Decodes base64 in a C string into a newly allocated aws_byte_buf.
 * Aborts if anything goes wrong.
 */
TESTLIB_API
struct aws_byte_buf easy_b64_decode(const char *b64_string);

/**
 * Verify that the idx'th element of keyring trace has all the
 * specified attributes. name_space and/or name may be set to
 * NULL to ignore those checks.
 */
TESTLIB_API
int assert_keyring_trace_record(const struct aws_array_list *keyring_trace,
                                size_t idx,
                                const char *name_space,
                                const char *name,
                                uint32_t flags);


#ifdef __cplusplus
}
#endif

#define RUN_TEST(expr) \
    do { \
        aws_reset_error(); \
        const char *test_desc = #expr; \
        fprintf(stderr, "[RUNNING] %s ...\r", test_desc); \
        int result = (expr); \
        fprintf(stderr, "%s %s    \n", result ? "\n[ FAILED]" : "[ PASSED]", test_desc); \
        if (result) return 1; \
    } while (0)

#endif
