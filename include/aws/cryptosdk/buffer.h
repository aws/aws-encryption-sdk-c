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

/**
 * Advances the cursor by 'len' bytes, without returning the old position. If the cursor does not have at least
 * 'len' bytes remaining, leaves the cursor unchanged and returns AWS_ERROR_SHORT_BUFFER. Otherwise, the cursor's
 * pointer and length are updated, and the function returns AWS_ERROR_SUCCESS.
 */
static inline int aws_byte_cursor_skip(struct aws_byte_cursor *cursor, size_t length) {
    struct aws_byte_cursor slice = aws_byte_cursor_advance_nospec(cursor, length);
    return slice.ptr ? AWS_ERROR_SUCCESS : AWS_ERROR_SHORT_BUFFER;
}

/**
 * Reads arbitrary data from pBuf to the output cursor identified by dest and len.
 *
 * If successful, pBuf->ptr is advanced len bytes, and AWS_ERROR_SUCCESS is returned.
 * Otherwise, returns AWS_ERROR_SHORT_BUFFER without changing any state.
 */
static inline int aws_byte_cursor_read(struct aws_byte_cursor * restrict pBuf, void * restrict dest, size_t len) {
    struct aws_byte_cursor slice = aws_byte_cursor_advance_nospec(pBuf, len);

    if (slice.ptr) {
        memcpy(dest, slice.ptr, len);
        return AWS_ERROR_SUCCESS;
    } else {
        return AWS_ERROR_SHORT_BUFFER;
    }
}

/**
 * Reads a single byte from pBuf, placing it in *var.
 *
 * If successful, *var contains the byte previously pointed-to by pBuf->ptr,
 * and AWS_ERROR_SUCCESS is returned. If pBuf had insufficient data, then AWS_ERROR_SHORT_BUFFER
 * is returned without changing any state.
 */
static inline int aws_byte_cursor_read_u8(struct aws_byte_cursor * restrict pBuf, uint8_t * restrict var) {
    return aws_byte_cursor_read(pBuf, var, 1);
}

/**
 * Reads a 16bit value in network byte order from pBuf, and places it in native byte order into var.
 * pBuf->ptr is not required to be aligned.
 *
 * If successful, *var contains the value previously pointed-to by pBuf->ptr (after byteswap, if required),
 * and AWS_ERROR_SUCCESS is returned. If pBuf had insufficient data, then AWS_ERROR_SHORT_BUFFER
 * is returned without changing any state.
 */
static inline int aws_byte_cursor_read_be16(struct aws_byte_cursor *pBuf, uint16_t *var) {
    int rv = aws_byte_cursor_read(pBuf, var, 2);

    if (aws_cryptosdk_likely(!rv)) {
        *var = ntohs(*var);
    }

    return rv;
}

/**
 * Reads a 32-bit value in network byte order from pBuf, and places it in native byte order into var.
 * pBuf->ptr is not required to be aligned.
 *
 * If successful, *var contains the value previously pointed-to by pBuf->ptr (after byteswap, if required),
 * and AWS_ERROR_SUCCESS is returned. If pBuf had insufficient data, then AWS_ERROR_SHORT_BUFFER
 * is returned without changing any state.
 */
static inline int aws_byte_cursor_read_be32(struct aws_byte_cursor *pBuf, uint32_t *var) {
    int rv = aws_byte_cursor_read(pBuf, var, 4);

    if (aws_cryptosdk_likely(!rv)) {
        *var = ntohl(*var);
    }

    return rv;
}

#endif // AWS_CRYPTOSDK_BUFFER_H
