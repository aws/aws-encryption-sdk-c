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

#include <aws/cryptosdk/private/compiler.h>
#include <aws/cryptosdk/error.h>

/**
 * A generic length-delimited binary buffer.
 * Note that the data within may not be nul-terminated.
 */
struct aws_cryptosdk_buffer {
    void *ptr;
    size_t len;
};

/**
 * Performs a bounds check, verifying that the buffer provided has 'len' bytes of space available.
 * If successful, pBuf->ptr is advanced length bytes, the old pointer placed in *pResult,
 * and AWS_ERROR_SUCCESS returned.
 * Otherwise (if there is insufficient space), AWS_ERROR_SHORT_BUFFER is returned, *pBuf is unchanged,
 * and *pResult is set to NULL
 *
 * If pResult is NULL, this function will discard the old buffer position instead of writing to *pResult.
 *
 * Arguments:
 *  * buf - a struct aws_cryptosdk_buffer *
 *  * len - Length to advance the buffer pointer by
 *  * pResult - A pointer to the pointer to which the original buffer pointer will be written.
 *
 * This function attempts to prevent the CPU from speculating an out-of-bounds read as a SPECTRE
 * mitigation.
 */
static inline int aws_cryptosdk_buffer_advance(struct aws_cryptosdk_buffer * pBuf, size_t length, uint8_t * restrict *pResult) {
    void *result = pBuf->ptr;

#if defined(AWS_CRYPTOSDK_P_USE_X86_64_ASM) && defined(AWS_CRYPTOSDK_P_SPECTRE_MITIGATIONS)
    void *zero = NULL;
    size_t original_len = pBuf->len;

    __asm__(
            "sub %[length], %[remaining_len]\n"
            // We expect that length remaining_len should decrease, but not below zero.
            // This means that CF=0. Note that CF does not behave the same way as if we
            // had added a negative number!
            "cmovc %[original_len], %[remaining_len]\n" // undo the length update
            "cmovc %[zero], %[length]\n"                // don't update ptr
            "cmovc %[zero], %[result]\n"                // return null to signal overflow

            // If we didn't zero out length, now's the time to update the pointer.
            // Here we also check if the size was >= 2^63
            "add %[length], %[ptr]\n"

            // Length is an out param here because we may clobber it. It's a
            // register (only) because we use it along with other parameters,
            // and we prefer those to be rm instead (because they may be
            // structure fields directly addressed).

            // The use of & prefixes tells GCC we will overwrite these values before we're done with
            // input registers. When this is missing some very subtle bugs happen, particularly at
            // higher optimization levels.
            : [length] "+&r" (length), [remaining_len] "+&rm" (pBuf->len), [ptr] "+&rm" (pBuf->ptr), [result] "+&rm" (result)
            // These must not be a register, as we're cmoving to fields that can (and potentially should)
            // be allocated to memory (and cmov can only take one memory argument).
            // They also cannot be an immediate due to cmov encoding limitations.
            : [zero] "r" (zero), [original_len] "r" (original_len)
            : "cc"
           );
#else
    if (length > pBuf->len) {
        result = NULL;
    } else {
        pBuf->ptr = (uint8_t*)pBuf->ptr + length;
        pBuf->len -= length;
    }
#endif
    if (aws_cryptosdk_likely(pResult)) {
        *pResult = result;
    }

    // We move this condition outside of the asm to allow better compiler optimization (e.g. elimination
    // of these constants if we're just going to test for nonzero anyway)
    return aws_cryptosdk_likely(result) ? AWS_ERROR_SUCCESS : AWS_ERROR_SHORT_BUFFER;
}
 
/**
 * Advances the buffer by 'len' bytes, without returning the old position. If the buffer does not have at least
 * 'len' bytes remaining, leaves the buffer unchanged and returns AWS_ERROR_SHORT_BUFFER. Otherwise, the buffer's
 * pointer and length are updated, and the function returns AWS_ERROR_SUCCESS.
 */
static inline int aws_cryptosdk_buffer_skip(struct aws_cryptosdk_buffer *buffer, size_t length) {
    uint8_t *ignored;
    return aws_cryptosdk_buffer_advance(buffer, length, &ignored);
}

/**
 * Reads arbitrary data from pBuf to the output buffer identified by dest and len.
 *
 * If successful, pBuf->ptr is advanced len bytes, and AWS_ERROR_SUCCESS is returned.
 * Otherwise, returns AWS_ERROR_SHORT_BUFFER without changing any state.
 */
static inline int aws_cryptosdk_buffer_read(struct aws_cryptosdk_buffer * restrict pBuf, void * restrict dest, size_t len) {
    uint8_t *pSource;

    if (aws_cryptosdk_buffer_advance(pBuf, len, &pSource)) {
        return AWS_ERROR_SHORT_BUFFER;
    }

    memcpy(dest, pSource, len);

    return AWS_ERROR_SUCCESS;
}

/**
 * Reads a single byte from pBuf, placing it in *var.
 *
 * If successful, *var contains the byte previously pointed-to by pBuf->ptr,
 * and AWS_ERROR_SUCCESS is returned. If pBuf had insufficient data, then AWS_ERROR_SHORT_BUFFER
 * is returned without changing any state.
 */
static inline int aws_cryptosdk_buffer_read_u8(struct aws_cryptosdk_buffer * restrict pBuf, uint8_t * restrict var) {
    return aws_cryptosdk_buffer_read(pBuf, var, 1);
}

/**
 * Reads a 16bit value in network byte order from pBuf, and places it in native byte order into var.
 * pBuf->ptr is not required to be aligned.
 *
 * If successful, *var contains the value previously pointed-to by pBuf->ptr (after byteswap, if required),
 * and AWS_ERROR_SUCCESS is returned. If pBuf had insufficient data, then AWS_ERROR_SHORT_BUFFER
 * is returned without changing any state.
 */
static inline int aws_cryptosdk_buffer_read_be16(struct aws_cryptosdk_buffer *pBuf, uint16_t *var) {
    int rv = aws_cryptosdk_buffer_read(pBuf, var, 2);

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
static inline int aws_cryptosdk_buffer_read_be32(struct aws_cryptosdk_buffer *pBuf, uint32_t *var) {
    int rv = aws_cryptosdk_buffer_read(pBuf, var, 4);

    if (aws_cryptosdk_likely(!rv)) {
        *var = ntohl(*var);
    }

    return rv;
}

#endif // AWS_CRYPTOSDK_BUFFER_H
