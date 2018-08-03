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
#ifndef AWS_CRYPTOSDK_TESTS_LIB_RAW_AES_MK_TEST_VECTORS_H
#define AWS_CRYPTOSDK_TESTS_LIB_RAW_AES_MK_TEST_VECTORS_H

#include <aws/cryptosdk/materials.h>

extern const uint8_t test_vector_master_key_id[39]; // includes null byte
extern const uint8_t test_vector_provider_id[14];   // includes null byte
extern const uint8_t test_vector_wrapping_key[32];  // no null terminator

/* aws_string *addresses* are values only known at runtime, even when defined with
 * AWS_STATIC_STRING_FROM_LITERAL, which prevents us from declaring static arrays
 * of strings. To get around this we define a function which adds the right set
 * of key-value pairs to the encryption context for each test vector.
 */
typedef void (*enc_context_builder)(struct aws_hash_table *);

struct raw_aes_mk_test_vector {
    enum aws_cryptosdk_aes_key_len raw_key_len;
    enum aws_cryptosdk_alg_id alg;
    const uint8_t * data_key;
    size_t data_key_len;
    const uint8_t * iv;
    const uint8_t * edk_bytes;
    size_t edk_bytes_len;
    enc_context_builder ec_builder;
};

extern struct raw_aes_mk_test_vector test_vectors[];

struct aws_cryptosdk_edk build_test_edk(const uint8_t * edk_bytes, size_t edk_len, const uint8_t * iv);

struct aws_cryptosdk_edk edk_from_test_vector(int idx);

static inline bool aws_cryptosdk_edk_eq(const struct aws_cryptosdk_edk * a, const struct aws_cryptosdk_edk * b) {
    return aws_byte_buf_eq(&a->enc_data_key, &b->enc_data_key) &&
        aws_byte_buf_eq(&a->provider_info, &b->provider_info) &&
        aws_byte_buf_eq(&a->provider_id, &b->provider_id);
}

#endif // AWS_CRYPTOSDK_TESTS_LIB_RAW_AES_MK_TEST_VECTORS_H
