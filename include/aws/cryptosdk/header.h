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

#ifndef AWS_CRYPTOSDK_HEADER_H
#define AWS_CRYPTOSDK_HEADER_H

#include <stdint.h>
#include <stdlib.h>
#include "aws/cryptosdk/error.h"
#include "aws/cryptosdk/buffer.h"

/**
 * Represents an immutable, parsed header.
 */
struct aws_cryptosdk_hdr;

/**
 * Used to pass encryption context key-value pairs.
 */
struct aws_cryptosdk_hdr_aad {
    struct aws_byte_buf key, value;
};

/**
 * Used to pass encrypted data key entries.
 */
struct aws_cryptosdk_hdr_edk {
    struct aws_byte_buf provider_id, provider_info, enc_data_key;
};

enum aws_cryptosdk_hdr_version {
    // Only one version is currently defined.
    AWS_CRYPTOSDK_HEADER_VERSION_1_0 = 0x01
};

enum aws_cryptosdk_hdr_type {
    // Only one data type is currently defined.
    AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED = 0x80
};

/**
 * Known algorithm suite names.
 * These follow the format:
 *   [cipher algorithm]_IV[iv length]_AUTH[authtag length]_KD[KDF algorithm]_SIG[Signature algorithm, or NONE]
 */
enum aws_cryptosdk_alg_id {
    AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384 = 0x0378,
    AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384 = 0x0346,
    AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256 = 0x0214,
    AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE  = 0x0178,
    AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE  = 0x0146,
    AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE  = 0x0114,
    AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE    = 0x0078,
    AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE    = 0x0046,
    AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE    = 0x0014
};

enum aws_cryptosdk_hdr_content_type {
    AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED = 0x01,
    AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED = 0x02
};

/**
 * Attempts to parse the header to determine how much space is needed for header data structures.
 *
 * If parsing was successful, returns AWS_ERR_OK. The amount of memory needed for the parsed header structure
 * is placed in header_space_needed, and the actual header length in header_length.
 *
 * If additional header data is required, returns AWS_CRYPTOSDK_ERR_SHORT_BUF.
 * If the header could not be parsed due to an unrecognized or corrupt format, returns AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT.
 *
 * This function performs only structural validation, and does not validate the header authentication tag.
 */
int aws_cryptosdk_hdr_preparse(const uint8_t *hdrbuf, size_t buflen, size_t *header_space_needed, size_t *header_length);

/**
 * Attempts to parse a header.
 * 
 * If parsing is successful, returns AWS_ERR_OK. *hdr points to the header
 * structure, which will be somewhere within outbuf. When the header structure
 * is no longer needed, simply discard the *hdr pointer and overwrite or free
 * outbuf.
 *
 * If additional header data is required, returns AWS_CRYPTOSDK_ERR_SHORT_BUF.
 * If the header could not be parsed due to an unrecognized or corrupt format,
 * returns AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT.
 * If outbuf is too small, returns AWS_ERR_OOM.
 *
 * This function performs only structural validation, and does not validate the header authentication tag.
 */
int aws_cryptosdk_hdr_parse(
    struct aws_cryptosdk_hdr **hdr,
    uint8_t *outbuf, size_t outlen,
    const uint8_t *inbuf, size_t inlen
);

uint16_t aws_cryptosdk_hdr_get_algorithm(const struct aws_cryptosdk_hdr *hdr);
size_t aws_cryptosdk_hdr_get_aad_count(const struct aws_cryptosdk_hdr *hdr);
size_t aws_cryptosdk_hdr_get_edk_count(const struct aws_cryptosdk_hdr *hdr);
size_t aws_cryptosdk_hdr_get_iv_len(const struct aws_cryptosdk_hdr *hdr);
size_t aws_cryptosdk_hdr_get_frame_len(const struct aws_cryptosdk_hdr *hdr);
int aws_cryptosdk_hdr_get_aad(const struct aws_cryptosdk_hdr *hdr, int index, struct aws_cryptosdk_hdr_aad *aad);
int aws_cryptosdk_hdr_get_edk(const struct aws_cryptosdk_hdr *hdr, int index, struct aws_cryptosdk_hdr_edk *edk);

int aws_cryptosdk_hdr_get_msgid(const struct aws_cryptosdk_hdr *hdr, struct aws_byte_buf *buf);
int aws_cryptosdk_hdr_get_authtag(const struct aws_cryptosdk_hdr *hdr, struct aws_byte_buf *buf);

int aws_cryptosdk_algorithm_is_known(uint16_t alg_id);
int aws_cryptosdk_algorithm_taglen(uint16_t alg_id);
int aws_cryptosdk_algorithm_ivlen(uint16_t alg_id);

#endif // AWS_CRYPTOSDK_HEADER_H
