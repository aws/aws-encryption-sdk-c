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
#ifndef AWS_CRYPTOSDK_ENC_CONTEXT_H
#define AWS_CRYPTOSDK_ENC_CONTEXT_H

#include <aws/common/hash_table.h>

/**
 * Initialize an encryption context, which is just an AWS hash table
 * that uses AWS strings as keys and values.
 *
 * See aws/common/hash_table.h for the interface to AWS hash tables,
 * and aws/common/string.h for the interface to AWS strings.
 *
 */
int aws_cryptosdk_enc_context_init(struct aws_allocator *alloc,
                                   struct aws_hash_table *enc_context);

/**
 * Clear the elements of an encryption context without deallocating the hash table.
 */
static inline void aws_cryptosdk_enc_context_clear(struct aws_hash_table *enc_context) {
    aws_hash_table_clear(enc_context);
}

/**
 * Deallocate an encryption context.
 */
static inline void aws_cryptosdk_enc_context_clean_up(struct aws_hash_table *enc_context) {
    aws_hash_table_clean_up(enc_context);
}

#endif // AWS_CRYPTOSDK_ENC_CONTEXT_H
