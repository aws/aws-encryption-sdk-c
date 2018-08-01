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
#ifndef AWS_CRYPTOSDK_PRIVATE_ENC_CONTEXT_H
#define AWS_CRYPTOSDK_PRIVATE_ENC_CONTEXT_H

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>

/**
 * Allocates byte buffer and puts serialized encryption context into buffer.
 *
 * On failure, nothing is allocated and all fields of byte buffer are zeroized.
 */
int aws_cryptosdk_serialize_enc_context_init(struct aws_allocator * alloc,
                                             struct aws_byte_buf * output,
                                             const struct aws_hash_table * enc_context);

#endif // AWS_CRYPTOSDK_PRIVATE_ENC_CONTEXT_H
