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

#ifndef AWS_CRYPTOSDK_BUFFER_H
#define AWS_CRYPTOSDK_BUFFER_H

#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h> // NULL
#include <string.h> // memcpy

#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/private/compiler.h>
#include <aws/cryptosdk/error.h>
 
// TODO: Move this to aws-c-common

/*
 * All aws_byte_cursor_read* functions read data from byte cursor and write it to somewhere else.
 * All aws_byte_cursor_write* functions read data from somewhere else and write it to the byte cursor.
 * All check that the byte cursor has enough space to do the read or write and fail cleanly when it does
 * not, returning a AWS_ERROR_SHORT_BUFFER error and not modifying the byte cursor.
 * All return AWS_ERROR_SUCCESS on success and update the pointer and length remaining in the byte cursor.
 */

/**
 * Reads specified length of data from byte cursor and copies it to the destination array.
 */
static inline int aws_byte_cursor_read(struct aws_byte_cursor * restrict cur, void * restrict dest, size_t len) {
    struct aws_byte_cursor slice = aws_byte_cursor_advance_nospec(cur, len);

    if (slice.ptr) {
        memcpy(dest, slice.ptr, len);
        return AWS_ERROR_SUCCESS;
    } else {
        return AWS_ERROR_SHORT_BUFFER;
    }
}

/**
 * Reads as many bytes from cursor as size of buffer, and copies them to buffer.
 */
static inline int aws_byte_cursor_read_and_fill_buffer(struct aws_byte_cursor * restrict cur, struct aws_byte_buf * restrict dest) {
    return aws_byte_cursor_read(cur, dest->buffer, dest->len);
}

/**
 * Reads a single byte from cursor, placing it in *var.
 */
static inline int aws_byte_cursor_read_u8(struct aws_byte_cursor * restrict cur, uint8_t * restrict var) {
    return aws_byte_cursor_read(cur, var, 1);
}

/**
 * Reads a 16-bit value in network byte order from cur, and places it in host byte order into var.
 */
static inline int aws_byte_cursor_read_be16(struct aws_byte_cursor *cur, uint16_t *var) {
    int rv = aws_byte_cursor_read(cur, var, 2);

    if (aws_cryptosdk_likely(!rv)) {
        *var = ntohs(*var);
    }

    return rv;
}

/**
 * Reads a 32-bit value in network byte order from cur, and places it in host byte order into var.
 */
static inline int aws_byte_cursor_read_be32(struct aws_byte_cursor *cur, uint32_t *var) {
    int rv = aws_byte_cursor_read(cur, var, 4);

    if (aws_cryptosdk_likely(!rv)) {
        *var = ntohl(*var);
    }

    return rv;
}

/**
 * Write specified number of bytes from array to byte cursor.
 */
static inline int aws_byte_cursor_write(struct aws_byte_cursor * restrict cur, const uint8_t * restrict src, size_t len) {
    struct aws_byte_cursor slice = aws_byte_cursor_advance_nospec(cur, len);

    if (slice.ptr) {
        memcpy(slice.ptr, src, len);
        return AWS_ERROR_SUCCESS;
    } else {
        return AWS_ERROR_SHORT_BUFFER;
    }
}

/**
 * Copies all bytes from buffer to cursor.
 */
static inline int aws_byte_cursor_write_from_whole_buffer(struct aws_byte_cursor * restrict cur, const struct aws_byte_buf * restrict src) {
    return aws_byte_cursor_write(cur, src->buffer, src->len);
}

/**
 * Copies one byte to cursor.
 */
static inline int aws_byte_cursor_write_u8(struct aws_byte_cursor * restrict cur, uint8_t c) {
    return aws_byte_cursor_write(cur, &c, 1);
}

/**
 * Writes a 16-bit integer in network byte order (big endian) to cursor.
 */
static inline int aws_byte_cursor_write_be16(struct aws_byte_cursor *cur, uint16_t x) {
    x = htons(x);
    return aws_byte_cursor_write(cur, (uint8_t *) &x, 2);
}

/**
 * Writes a 32-bit integer in network byte order (big endian) to cursor.
 */
static inline int aws_byte_cursor_write_be32(struct aws_byte_cursor *cur, uint32_t x) {
    x = htonl(x);
    return aws_byte_cursor_write(cur, (uint8_t *) &x, 4);
}

#endif // AWS_CRYPTOSDK_BUFFER_H
