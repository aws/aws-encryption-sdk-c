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
 * write the namespace into the provider ID field of EDKs and the key name into
 * the provider info field of EDKs, and all new keyring implementations MUST
 * follow this practice. For legacy reasons, the raw AES keyring includes other
 * data in the provider ID field, but only the first part of that field (the
 * wrapping key name) corresponds to what is stored in the key name field
 * of this struct.
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
 * The canonical example of a wrapping key is a KMS CMK, for which the namespace
 * is "aws-kms" and the name is the key ARN.
 */
struct aws_cryptosdk_wrapping_key {
    struct aws_string *namespace;
    struct aws_string *name;
};

/**
 * When a keyring is called it produces a trace of what actions it took with
 * the different wrapping keys it manages. The trace is an array list of these
 * items.
 */
struct aws_cryptosdk_keyring_trace_item {
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

AWS_CRYPTOSDK_API
int aws_cryptosdk_wrapping_key_init(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_wrapping_key *wrapping_key,
    const struct aws_string *namespace,
    const struct aws_string *name);

AWS_CRYPTOSDK_API
void aws_cryptosdk_wrapping_key_clean_up(struct aws_cryptosdk_wrapping_key *wrapping_key);

AWS_CRYPTOSDK_API
int aws_cryptosdk_keyring_trace_init(struct aws_allocator *alloc, struct aws_array_list *trace);

AWS_CRYPTOSDK_API
void aws_cryptosdk_keyring_trace_clean_up(struct aws_array_list *trace);

AWS_CRYPTOSDK_API
void aws_cryptosdk_keyring_trace_clear(struct aws_array_list *trace);

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_KEYRING_TRACE_H
