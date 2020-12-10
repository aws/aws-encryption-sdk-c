/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/private/cipher.h>

/* Asserts that the contents of two aws_byte_buf objects match */
void assert_byte_buf_contents_match(const struct aws_byte_buf *const lhs, const struct aws_byte_buf *const rhs);

/* Compares the contents of two aws_byte_buf objects */
bool aws_byte_buf_contents_match(const struct aws_byte_buf *const lhs, const struct aws_byte_buf *const rhs);

/* Compares the contents of a content key with a data key up to max_len */
bool key_contents_match(const struct content_key *ckey, const struct data_key *dkey, const size_t max_len);
