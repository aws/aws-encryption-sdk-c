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
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <aws/common/common.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/enc_context.h>
#include "../unit/testing.h"
#include "testutil.h"

#ifdef _MSC_VER
#pragma warning(disable: 4774) // printf format string is not a string literal
#endif

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


int test_enc_context_init_and_fill(struct aws_hash_table *enc_context) {
    TEST_ASSERT_SUCCESS(aws_cryptosdk_enc_context_init(aws_default_allocator(), enc_context));

    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_1, "The night is dark");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_1, "and full of terrors");
    aws_hash_table_put(enc_context, enc_context_key_1, (void *)enc_context_val_1, NULL);

    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_2, "You Know Nothing");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_2, "James Bond");
    aws_hash_table_put(enc_context, enc_context_key_2, (void *)enc_context_val_2, NULL);

    return 0;
}
