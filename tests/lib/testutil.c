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

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <aws/common/common.h>
#include <aws/common/encoding.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/enc_context.h>
#include <aws/cryptosdk/keyring_trace.h>
#include "../unit/testing.h"
#include "testutil.h"

#ifdef _MSC_VER
#pragma warning(disable: 4774) // printf format string is not a string literal
#endif

void byte_buf_printf(struct aws_byte_buf *buf, struct aws_allocator *alloc, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);

    int size = vsnprintf(NULL, 0, fmt, ap);
    if (aws_byte_buf_init(buf, alloc, size + 1)) {
        abort();
    }
    va_end(ap);

    va_start(ap, fmt);
    buf->len = vsnprintf((char *)buf->buffer, buf->capacity, fmt, ap);

    va_end(ap);
}

void hexdump(FILE *fd, const uint8_t *buf, size_t size) {
    for (size_t row = 0; row < size; row += 16) {
        fprintf(fd, "%08zx ", row);
        for (int idx = 0; idx < 16; idx++) {
            if (idx + row < size) {
                fprintf(fd, "%s%02x", (idx == 8) ? "  " : " ", buf[idx + row]);
            } else {
                fprintf(fd, (idx == 8) ? "    " : "   ");
            }
        }
        fprintf(fd, "  |");
        for (int idx = 0; idx < 16 && idx + row < size; idx++) {
            uint8_t ch = buf[idx + row];
            fprintf(fd, "%c", isprint(ch) ? ch : '.');
        }
        fprintf(fd, "|\n");
    }
}

int test_loadfile(const char *filename, uint8_t **buf, size_t *datasize) {
    uint8_t *tmpbuf = NULL;
    FILE *fp = fopen(filename, "rb");

    if (!fp) {
        return 1;
    }

    size_t bufsz = 128;
    size_t offset = 0;

    tmpbuf = malloc(bufsz);

    if (!tmpbuf) {
        fclose(fp);
        errno = ENOMEM;
        return 1;
    }

    while (!feof(fp)) {
        if (offset == bufsz) {
            size_t newsz = bufsz * 2;
            if (newsz <= bufsz) {
                errno = ENOMEM;
                goto failure;
            }

            uint8_t *newptr = realloc(tmpbuf, newsz);
            if (!newptr) {
                errno = ENOMEM;
                goto failure;
            }

            tmpbuf = newptr;
            bufsz = newsz;
        }

        size_t nread = fread(tmpbuf + offset, 1, bufsz - offset, fp);
        if (ferror(fp)) {
            errno = EIO;
            goto failure;
        }

        offset += nread;
    }

    {
        *buf = realloc(tmpbuf, offset);
        if (!*buf) {
            errno = ENOMEM;
            goto failure;
        }

        *datasize = offset;
        if (fp) fclose(fp);
        return 0;
    }

failure:
    /*
     *  we need this semicolon as we can't have a variable declaration right
     * after a label
     */
    ;

    int saved_errno = errno;

    if (tmpbuf) free(tmpbuf);
    if (fp) fclose(fp);

    errno = saved_errno;

    return 1;
}


int test_enc_context_init_and_fill(struct aws_allocator *alloc,
                                   struct aws_hash_table *enc_context) {
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(alloc, enc_context));

    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_1, "The night is dark");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_1, "and full of terrors");
    TEST_ASSERT_SUCCESS(aws_hash_table_put(enc_context, enc_context_key_1,
                                           (void *)enc_context_val_1, NULL));

    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_2, "You Know Nothing");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_2, "James Bond");
    TEST_ASSERT_SUCCESS(aws_hash_table_put(enc_context, enc_context_key_2,
                                           (void *)enc_context_val_2, NULL));

    return 0;
}

struct aws_byte_buf easy_b64_decode(const char *b64_string) {
    struct aws_byte_cursor input = aws_byte_cursor_from_c_str(b64_string);
    struct aws_byte_buf output;
    size_t decoded_len;

    if (aws_base64_compute_decoded_len(&input, &decoded_len)
        || aws_byte_buf_init(&output, aws_default_allocator(), decoded_len)
        || aws_base64_decode(&input, &output)) {
        abort();
    }

    return output;
}

int assert_keyring_trace_item(const struct aws_array_list *keyring_trace,
                              size_t idx,
                              uint32_t flags,
                              const char *name_space,
                              const char *name) {
    struct aws_cryptosdk_keyring_trace_item item;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(keyring_trace, (void *)&item, idx));
    TEST_ASSERT_INT_EQ(item.flags, flags);
    if (name_space) {
        const struct aws_byte_cursor ns = aws_byte_cursor_from_c_str(name_space);
        TEST_ASSERT(aws_string_eq_byte_cursor(item.wrapping_key.name_space, &ns));
    }
    if (name) {
        const struct aws_byte_cursor n = aws_byte_cursor_from_c_str(name);
        TEST_ASSERT(aws_string_eq_byte_cursor(item.wrapping_key.name, &n));
    }
    return 0;
}
