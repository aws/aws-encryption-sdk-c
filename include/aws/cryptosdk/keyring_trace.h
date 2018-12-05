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

#ifndef AWS_CRYPTOSDK_KEYRING_TRACE_H
#define AWS_CRYPTOSDK_KEYRING_TRACE_H

#include <aws/common/array_list.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/exports.h>

/**
 * The identifiers which are used to indicate which wrapping key or "master key"
 * was used to do data key encryption by a keyring. Most keyring implementations
 * write the name_space into the provider ID field of EDKs and the key name into
 * the provider info field of EDKs, and all new keyring implementations should
 * follow this practice. For legacy reasons, the raw AES keyring includes other
 * data in the provider ID field, but only the first part of that field (the
 * wrapping key name) corresponds to what is stored in the name field here.
 *
 * Note: "Master Key (MK)" is used as a class name in the Java and Python
 * implementations of the AWS Encryption SDK, where it is an abstraction of a
 * single wrapping key, and "Master Key Provider (MKP)" is a class that provides
 * multiple wrapping keys. In the AWS Encryption SDK for C, the keyring
 * replaces both of these concepts. It handles one or multiple wrapping keys,
 * which makes it similar to an MKP, but from an API perspective it is in some
 * ways closer to an MK. In order to avoid confusion with the MK class of the
 * Java and Python SDKs, we always refer to a single entity used by a keyring
 * for data key encryption as a wrapping key.
 *
 * The motivating example of a wrapping key is a KMS CMK, for which the name_space
 * is "aws-kms" and the name is the key ARN.
 *
 * Do not handle this structure by itself. It exists primarily as a semantic
 * label to link the name_space and name within the trace record.
 */
struct aws_cryptosdk_wrapping_key {
    struct aws_string *name_space;
    struct aws_string *name;
};

/**
 * When a keyring is called it produces a trace of what actions it took with
 * the different wrapping keys it manages. The trace is a list of these records.
 */
struct aws_cryptosdk_keyring_trace_record {
    struct aws_cryptosdk_wrapping_key wrapping_key;
    uint32_t flags;
};

/**
 * Bit flags used to indicate which actions a particular wrapping key has done.
 */
#define AWS_CRYPTOSDK_WRAPPING_KEY_GENERATED_DATA_KEY 1
#define AWS_CRYPTOSDK_WRAPPING_KEY_ENCRYPTED_DATA_KEY (1 << 1)
#define AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY (1 << 2)
#define AWS_CRYPTOSDK_WRAPPING_KEY_SIGNED_ENC_CTX     (1 << 3)
#define AWS_CRYPTOSDK_WRAPPING_KEY_VERIFIED_ENC_CTX   (1 << 4)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Add a record to the trace with the specified name_space, name, and flags.
 * Makes duplicates of name_space and name strings. Will be deallocated
 * when the keyring trace object is cleared or cleaned up.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_keyring_trace_add_record(struct aws_allocator *alloc,
                                           struct aws_array_list *trace,
                                           const struct aws_string *name_space,
                                           const struct aws_string *name,
                                           uint32_t flags);

/**
 * Same as aws_cryptosdk_keyring_trace_add_record except it takes C strings
 * instead of AWS strings.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_keyring_trace_add_record_c_str(struct aws_allocator *alloc,
                                                 struct aws_array_list *trace,
                                                 const char *name_space,
                                                 const char *name,
                                                 uint32_t flags);

/**
 * Initialize a keyring trace.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_keyring_trace_init(struct aws_allocator *alloc,
                                     struct aws_array_list *trace);

/**
 * Deallocate all memory from a keyring trace.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_keyring_trace_clean_up(struct aws_array_list *trace);

/**
 * Deallocate and remove all records from a keyring trace, but do not
 * deallocate the keyring trace itself.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_keyring_trace_clear(struct aws_array_list *trace);

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_KEYRING_TRACE_H
