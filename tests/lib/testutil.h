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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Formats a string using printf format specifiers, and places it into buf, allocating space using alloc.
 * Aborts on allocation failure.
 */
void byte_buf_printf(struct aws_byte_buf *buf, struct aws_allocator *alloc, const char *fmt, ...);

/* 
 * Loads a file from disk into a newly malloc'd buffer.
 * Returns 0 on success, 1 on failure (examine errno for details)
 */
int test_loadfile(const char *filename, uint8_t **buf, size_t *datasize);

/*
 * Performs a human-readable hexdump of the given buffer
 */
void hexdump(FILE *fd, const uint8_t *buf, size_t size);

/**
 * Creates and initializes with fixed strings an encryption context
 * Note: enc_context needs to be cleaned using aws_hash_table_clean_up
 * @param enc_context Output variable with an initialized hash_table
 * @return
 */
int test_enc_context_init_and_fill(struct aws_hash_table *enc_context);

/**
 * Decodes base64 in a C string into a newly allocated aws_byte_buf.
 * Aborts if anything goes wrong.
 */
struct aws_byte_buf easy_b64_decode(const char *b64_string);

#ifdef __cplusplus
}
#endif

#define RUN_TEST(expr) \
    do { \
        const char *test_desc = #expr; \
        fprintf(stderr, "[RUNNING] %s ...\r", test_desc); \
        int result = (expr); \
        fprintf(stderr, "%s %s    \n", result ? "\n[ FAILED]" : "[ PASSED]", test_desc); \
        if (result) return 1; \
    } while (0)

#endif
