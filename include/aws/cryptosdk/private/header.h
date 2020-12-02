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
#include <aws/common/hash_table.h>
#include "aws/cryptosdk/header.h"
#include "aws/cryptosdk/materials.h"  // struct aws_cryptosdk_edk

struct aws_cryptosdk_hdr {
    struct aws_allocator *alloc;

    uint16_t alg_id;

    uint32_t frame_len;

    struct aws_byte_buf iv, auth_tag, message_id, alg_suite_data;

    // aws_string * -> aws_string *
    struct aws_hash_table enc_ctx;
    struct aws_array_list edk_list;

    // number of bytes of header except for IV and auth tag,
    // i.e., exactly the bytes that get authenticated
    size_t auth_len;
};

enum aws_cryptosdk_hdr_type {
    // Only one data type is currently defined.
    AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED = 0x80
};

enum aws_cryptosdk_hdr_content_type {
    AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED = 0x01,
    AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED    = 0x02
};

/**
 * Initializes the header datastructure; on return, all fields are zeroed,
 * except for enc_ctx and edk_tbl, which are empty.
 */
int aws_cryptosdk_hdr_init(struct aws_cryptosdk_hdr *hdr, struct aws_allocator *alloc);

/**
 * Frees all memory which has been allocated to hdr object and zeroizes hdr.
 * This method is idempotent - that is, it can safely be called multiple times
 * on the same header without an intervening init; however it cannot be called
 * on an _uninitialized_ header.
 */
void aws_cryptosdk_hdr_clean_up(struct aws_cryptosdk_hdr *hdr);

/**
 * Resets the header to the same state as it would have after hdr_init
 */
void aws_cryptosdk_hdr_clear(struct aws_cryptosdk_hdr *hdr);

/**
 * Reads raw header data from src and populates hdr with all of the information about the
 * message. hdr must have been initialized with aws_cryptosdk_hdr_init.
 *
 * This function will clear the header before parsing, and will leave the header in a cleared
 * state on failure.
 */
int aws_cryptosdk_hdr_parse(struct aws_cryptosdk_hdr *hdr, struct aws_byte_cursor *cursor);

/**
 * Parses the header version from the cursor into *header_version.
 */
int aws_cryptosdk_priv_hdr_parse_header_version(
    struct aws_cryptosdk_hdr *hdr, uint8_t *header_version, struct aws_byte_cursor *cur);

/**
 * Parses the message type from the cursor and asserts that it equals
 * AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED.
 */
int aws_cryptosdk_priv_hdr_parse_message_type(struct aws_cryptosdk_hdr *hdr, struct aws_byte_cursor *cur);

/**
 * Parses the algorithm ID from the cursor into hdr->alg_id and sets *alg_props
 * to the corresponding aws_cryptosdk_alg_properties struct.
 */
int aws_cryptosdk_priv_hdr_parse_alg_id(
    struct aws_cryptosdk_hdr *hdr,
    const struct aws_cryptosdk_alg_properties **alg_props,
    uint8_t header_version,
    struct aws_byte_cursor *cur);

/**
 * Parses the message ID from the cursor into hdr->message_id, using alg_props
 * to determine the correct length of message ID.
 */
int aws_cryptosdk_priv_hdr_parse_message_id(
    struct aws_cryptosdk_hdr *hdr, const struct aws_cryptosdk_alg_properties *alg_props, struct aws_byte_cursor *cur);

/**
 * Parses the AAD length and AAD raw data from the cursor, deserializing the
 * raw data into hdr->enc_ctx.
 */
int aws_cryptosdk_priv_hdr_parse_aad(struct aws_cryptosdk_hdr *hdr, struct aws_byte_cursor *cur);

/**
 * Parses the EDK count and EDKs' raw data from the cursor, deserializing the
 * raw data into hdr->edk_list.
 */
int aws_cryptosdk_priv_hdr_parse_edks(struct aws_cryptosdk_hdr *hdr, struct aws_byte_cursor *cur);

/**
 * Parses the content type from the cursor into *content_type.
 */
int aws_cryptosdk_priv_hdr_parse_content_type(
    struct aws_cryptosdk_hdr *hdr, uint8_t *content_type, struct aws_byte_cursor *cur);

/**
 * Parses the 32-bit reserved field from the cursor and asserts that it is
 * equal to zero.
 */
int aws_cryptosdk_priv_hdr_parse_reserved(struct aws_cryptosdk_hdr *hdr, struct aws_byte_cursor *cur);

/**
 * Parses the IV length into *iv_len and asserts that it is correct for
 * hdr->alg_id.
 */
int aws_cryptosdk_priv_hdr_parse_iv_len(struct aws_cryptosdk_hdr *hdr, uint8_t *iv_len, struct aws_byte_cursor *cur);

/**
 * Parses the frame length into hdr->frame_len and asserts that it is
 * consistent with content_type.
 */
int aws_cryptosdk_priv_hdr_parse_frame_len(
    struct aws_cryptosdk_hdr *hdr, uint8_t content_type, struct aws_byte_cursor *cur);

/**
 * Parses the algorithm suite data into hdr->alg_suite_data, using alg_props to
 * determine the appropriate length.
 */
int aws_cryptosdk_priv_hdr_parse_alg_suite_data(
    struct aws_cryptosdk_hdr *hdr, const struct aws_cryptosdk_alg_properties *alg_props, struct aws_byte_cursor *cur);

/**
 * Parses the IV into hdr->iv, using iv_len as the length.
 */
int aws_cryptosdk_priv_hdr_parse_iv(struct aws_cryptosdk_hdr *hdr, uint8_t iv_len, struct aws_byte_cursor *cur);

/**
 * Parses the auth tag into hdr->auth_tag, using hdr->alg_id to determine the
 * tag length.
 */
int aws_cryptosdk_priv_hdr_parse_auth_tag(struct aws_cryptosdk_hdr *hdr, struct aws_byte_cursor *cur);

/**
 * Clears hdr and raises AWS_ERROR_SHORT_BUFFER. Used when reading from a
 * buffer with insufficient data to parse.
 */
int aws_cryptosdk_priv_hdr_parse_err_short_buf(struct aws_cryptosdk_hdr *hdr);

/**
 * Clears hdr and raises AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT. Used for parse
 * errors that indicate a malformed message header, such as unrecognized field
 * constants and mismatches between values parsed from the header and those
 * defined by the algorithm suite.
 */
int aws_cryptosdk_priv_hdr_parse_err_generic(struct aws_cryptosdk_hdr *hdr);

/**
 * Clears hdr and returns AWS_OP_ERR without raising a new error. Used to
 * indicate allocation failure during parsing.
 */
int aws_cryptosdk_priv_hdr_parse_err_mem(struct aws_cryptosdk_hdr *hdr);

/**
 * Clears hdr and returns AWS_OP_ERR without raising a new error. Used to
 * rethrow errors that arise from functions called in order to parse a header
 * field.
 */
int aws_cryptosdk_priv_hdr_parse_err_rethrow(struct aws_cryptosdk_hdr *hdr);

/**
 * Reads information from already parsed hdr object and determines how many bytes are
 * needed to serialize.
 *
 * Returns number of bytes, or zero if hdr was not parsed correctly.
 *
 * Warning: running this on a hdr which has not already been run through
 * aws_cryptosdk_hdr_parse_init (or which has been zeroized) can result in a seg fault.
 */
int aws_cryptosdk_hdr_size(const struct aws_cryptosdk_hdr *hdr);

/**
 * Attempts to write a parsed header.
 *
 * The number of bytes written to outbuf is placed at *bytes_written. If outbuf is too
 * small, returns AWS_OP_ERR, sets the error code to AWS_ERROR_SHORT_BUFFER, and zeroizes
 * the output buffer.
 *
 * Using aws_cryptosdk_hdr_size to determine how much memory to allocate to outbuf ahead
 * of time guarantees that the short buffer error will not occur.
 */
int aws_cryptosdk_hdr_write(const struct aws_cryptosdk_hdr *hdr, size_t *bytes_written, uint8_t *outbuf, size_t outlen);

/**
 * Returns number of bytes in auth tag for known algorithms, -1 for unknown algorithms.
 */
int aws_cryptosdk_private_algorithm_taglen(uint16_t alg_id);

/**
 * Returns number of bytes in IV for known algorithms, -1 for unknown algorithms.
 */
int aws_cryptosdk_private_algorithm_ivlen(uint16_t alg_id);

/**
 * Returns the total length of statically sized fields for known header
 * versions, or -1 for unknown header versions.
 */
int aws_cryptosdk_private_header_version_static_fields_len(uint8_t header_version);

/**
 * Returns true for key-committing algorithms, or false otherwise.
 */
bool aws_cryptosdk_algorithm_is_committing(uint16_t alg_id);

#endif  // AWS_CRYPTOSDK_PRIVATE_HEADER_H
