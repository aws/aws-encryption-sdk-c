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

#include <aws/cryptosdk/exports.h>

#include <aws/common/hash_table.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup enc_context Encryption Context utilities
 *
 * The encryption context is a string-to-string map of contextual information
 * that is cryptographically bound to the message. We represent the encryption
 * context as an aws_hash_table mapping from aws_string * to aws_string *;
 * for the most part, aws_hash_table methods are used to manipulate these structures,
 * but we provide some higher-level helper methods in this section. These helpers
 * will mostly be of interest to developers of custom CMMs or keyrings.
 * @{
 */

/**
 * Initialize an encryption context, which is just an AWS hash table
 * that uses AWS strings as keys and values. The hash table will call
 * aws_string_destroy to destroy keys and values on destruction of
 * the hash table itself.
 *
 * See aws/common/hash_table.h for the interface to AWS hash tables,
 * and aws/common/string.h for the interface to AWS strings.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_enc_context_init(struct aws_allocator *alloc,
                                   struct aws_hash_table *enc_context);

/**
 * Clear the elements of an encryption context without deallocating the hash table.
 * This is equivalent to aws_hash_table_clear, but provided as an alias for clarity.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_enc_context_clear(struct aws_hash_table *enc_context) {
    aws_hash_table_clear(enc_context);
}

/**
 * Deallocate an encryption context.
 * This is equivalent to aws_hash_table_clean_up, but provided as an alias for clarity.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_enc_context_clean_up(struct aws_hash_table *enc_context) {
    aws_hash_table_clean_up(enc_context);
}

/**
 * Copies the contents of the 'src' encryption context into the 'dest' encryption context.
 * 'dest' must be pre-allocated.
 *
 * This method will reuse pre-existing entries in dest that match the values in src, and
 * will also reuse aws_strings with a NULL allocator in src. Any other values will be copied
 * into newly allocated memory using the given allocator.
 *
 * If this function returns an error, the contents of dest are unspecified, but are in a state
 * where aws_cryptosdk_enc_context_clear or aws_cryptosdk_enc_context_clean_up can be safely 
 * used without leaking memory.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_enc_context_clone(
    struct aws_allocator *alloc,
    struct aws_hash_table *dest,
    const struct aws_hash_table *src
);

/** @} */ // end of doxygen group

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_ENC_CONTEXT_H
