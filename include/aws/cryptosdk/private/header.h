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

#ifndef AWS_CRYPTOSDK_PRIVATE_HEADER_H
#define AWS_CRYPTOSDK_PRIVATE_HEADER_H

#include <aws/common/byte_buf.h>
#include "aws/cryptosdk/header.h"
#include "aws/cryptosdk/materials.h" // struct aws_cryptosdk_edk

#define MESSAGE_ID_LEN 16

/**
 * Used to pass encryption context key-value pairs.
 */
struct aws_cryptosdk_hdr_aad {
    struct aws_byte_buf key, value;
};

struct aws_cryptosdk_hdr {
    uint16_t alg_id;

    uint16_t aad_count;
    uint16_t edk_count;
    uint32_t frame_len;

    struct aws_byte_buf iv, auth_tag;

    uint8_t message_id[MESSAGE_ID_LEN];

    struct aws_cryptosdk_hdr_aad *aad_tbl;
    struct aws_cryptosdk_edk *edk_tbl;

    // number of bytes of header except for IV and auth tag,
    // i.e., exactly the bytes that get authenticated
    size_t auth_len;
};

enum aws_cryptosdk_hdr_version {
    // Only one version is currently defined.
    AWS_CRYPTOSDK_HEADER_VERSION_1_0 = 0x01
};

enum aws_cryptosdk_hdr_type {
    // Only one data type is currently defined.
    AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED = 0x80
};

enum aws_cryptosdk_hdr_content_type {
    AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED = 0x01,
    AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED = 0x02
};

/**
 * Frees all memory which has been allocated to hdr object and zeroizes hdr.
 * This is idempotent. Multiple frees are safe.
 */
void aws_cryptosdk_hdr_free(struct aws_allocator * allocator, struct aws_cryptosdk_hdr *hdr);

/**
 * Reads raw header data from src and populates hdr with all of the information about the message.
 * hdr is assumed to be an uninitialized hdr struct when this is called. If hdr has any memory already allocated to it,
 * that memory will be lost.
 * If this succeeds, hdr will have memory allocated to it, which must be freed with aws_cryptosdk_hdr_free.
 * If this fails, no memory will be allocated and hdr will be zeroized.
 */
int aws_cryptosdk_hdr_parse(struct aws_allocator * allocator, struct aws_cryptosdk_hdr *hdr, const uint8_t *src, size_t src_len);

/**
 * Reads information from already parsed hdr object and determines how many bytes are needed to serialize.
 * Returns number of bytes, or zero if hdr was not parsed correctly.
 *
 * Warning: running this on a hdr which has not already been run through aws_cryptosdk_hdr_parse (or which has been zeroized)
 * can result in a seg fault.
 */
int aws_cryptosdk_hdr_size(const struct aws_cryptosdk_hdr *hdr);

/**
 * Attempts to write a parsed header.
 *
 * The number of bytes written to outbuf is placed at *bytes_written.
 * If outbuf is too small, returns AWS_ERR_OOM and zeroizes the output buffer.
 *
 * Using aws_cryptosdk_hdr_size to determine how much memory to allocate to outbuf ahead of time prevents AWS_ERR_OOM.
 */
int aws_cryptosdk_hdr_write(const struct aws_cryptosdk_hdr *hdr, size_t * bytes_written, uint8_t *outbuf, size_t outlen);

/**
 * Returns 1 if alg_id is a known value, 0 if not.
 */
int aws_cryptosdk_algorithm_is_known(uint16_t alg_id);

/**
 * Returns number of bytes in auth tag for known algorithms, -1 for unknown algorithms.
 */
int aws_cryptosdk_algorithm_taglen(uint16_t alg_id);

/**
 * Returns number of bytes in IV for known algorithms, -1 for unknown algorithms.
 */
int aws_cryptosdk_algorithm_ivlen(uint16_t alg_id);

#endif // AWS_CRYPTOSDK_PRIVATE_HEADER_H
