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
#ifndef AWS_CRYPTOSDK_PRIVATE_ENC_CTX_H
#define AWS_CRYPTOSDK_PRIVATE_ENC_CTX_H

#include <aws/common/byte_buf.h>
#include <aws/cryptosdk/enc_ctx.h>

/**
 * Computes the size of a serialized encryption context.
 *
 * If the context is too large, raises AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED.
 */
int aws_cryptosdk_context_size(size_t *size, const struct aws_hash_table *enc_ctx);

/**
 * Serializes an encryption context into the given buffer, which must be preallocated.
 * The serialized context will be appended to the buffer (failing if it hits the buffer's capacity).
 * The passed allocator is used for temporary working memory only.
 */
int aws_cryptosdk_context_serialize(
    struct aws_allocator *alloc, struct aws_byte_buf *output, const struct aws_hash_table *enc_ctx);

/**
 * Deserializes an encryption context from the given cursor, which will be advanced accordingly.
 */
int aws_cryptosdk_context_deserialize(
    struct aws_allocator *alloc, struct aws_hash_table *enc_ctx, struct aws_byte_cursor *cursor);

#endif  // AWS_CRYPTOSDK_PRIVATE_ENC_CTX_H
