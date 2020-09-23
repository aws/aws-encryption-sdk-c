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

#include "testutil.h"
#include <aws/common/common.h>
#include <aws/common/encoding.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/keyring_trace.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "../unit/testing.h"

#ifdef _MSC_VER
#    pragma warning(disable : 4774)  // printf format string is not a string literal
#endif

TESTLIB_API
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

TESTLIB_API
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

TESTLIB_API
int test_loadfile(const char *filename, uint8_t **buf, size_t *datasize) {
    uint8_t *tmpbuf = NULL;
    FILE *fp        = fopen(filename, "rb");

    if (!fp) {
        return 1;
    }

    size_t bufsz  = 128;
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
            bufsz  = newsz;
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

AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_key_1, "The night is dark");
AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_val_1, "and full of terrors");
AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_key_2, "You Know Nothing");
AWS_STATIC_STRING_FROM_LITERAL(enc_ctx_val_2, "James Bond");

TESTLIB_API
int test_enc_ctx_fill(struct aws_hash_table *enc_ctx) {
    TEST_ASSERT_SUCCESS(aws_hash_table_put(enc_ctx, enc_ctx_key_1, (void *)enc_ctx_val_1, NULL));

    TEST_ASSERT_SUCCESS(aws_hash_table_put(enc_ctx, enc_ctx_key_2, (void *)enc_ctx_val_2, NULL));

    return 0;
}

TESTLIB_API
int assert_enc_ctx_fill(const struct aws_hash_table *enc_ctx) {
    struct aws_hash_element *elem;
    const struct aws_string *val;

    TEST_ASSERT_SUCCESS(aws_hash_table_find(enc_ctx, enc_ctx_key_1, &elem));
    TEST_ASSERT_ADDR_NOT_NULL(elem);
    val = (const struct aws_string *)elem->value;
    TEST_ASSERT(aws_string_eq(val, enc_ctx_val_1));

    TEST_ASSERT_SUCCESS(aws_hash_table_find(enc_ctx, enc_ctx_key_2, &elem));
    TEST_ASSERT_ADDR_NOT_NULL(elem);
    val = (const struct aws_string *)elem->value;
    TEST_ASSERT(aws_string_eq(val, enc_ctx_val_2));
    return 0;
}

TESTLIB_API
struct aws_string *easy_b64_encode(const uint8_t *data, size_t len) {
    struct aws_byte_cursor input = aws_byte_cursor_from_array(data, len);
    struct aws_byte_buf output;
    size_t encoded_len;

    if (aws_base64_compute_encoded_len(input.len, &encoded_len) ||
        aws_byte_buf_init(&output, aws_default_allocator(), encoded_len) || aws_base64_encode(&input, &output)) {
        abort();
    }

    struct aws_string *str = aws_string_new_from_array(aws_default_allocator(), output.buffer, encoded_len);
    if (!str) abort();

    aws_byte_buf_clean_up(&output);

    return str;
}

TESTLIB_API
struct aws_byte_buf easy_b64_decode(const char *b64_string) {
    struct aws_byte_cursor input = aws_byte_cursor_from_c_str(b64_string);
    struct aws_byte_buf output;
    size_t decoded_len;

    if (aws_base64_compute_decoded_len(&input, &decoded_len) ||
        aws_byte_buf_init(&output, aws_default_allocator(), decoded_len) || aws_base64_decode(&input, &output)) {
        abort();
    }

    return output;
}

TESTLIB_API
int assert_keyring_trace_record(
    const struct aws_array_list *keyring_trace, size_t idx, const char *name_space, const char *name, uint32_t flags) {
    struct aws_cryptosdk_keyring_trace_record record;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(keyring_trace, (void *)&record, idx));
    TEST_ASSERT_INT_EQ(record.flags, flags);
    if (name_space) {
        const struct aws_byte_cursor ns = aws_byte_cursor_from_c_str(name_space);
        TEST_ASSERT(aws_string_eq_byte_cursor(record.wrapping_key_namespace, &ns));
    }
    if (name) {
        const struct aws_byte_cursor n = aws_byte_cursor_from_c_str(name);
        TEST_ASSERT(aws_string_eq_byte_cursor(record.wrapping_key_name, &n));
    }
    return 0;
}
