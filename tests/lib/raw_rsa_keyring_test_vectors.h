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
#ifndef AWS_CRYPTOSDK_TESTS_LIB_RAW_RSA_KR_TEST_VECTORS_H
#define AWS_CRYPTOSDK_TESTS_LIB_RAW_RSA_KR_TEST_VECTORS_H

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/materials.h>

struct aws_cryptosdk_keyring *raw_rsa_keyring_tv_new(
    struct aws_allocator *alloc, enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

struct aws_cryptosdk_keyring *raw_rsa_keyring_tv_new_with_wrong_key(
    struct aws_allocator *alloc, enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode);

bool raw_rsa_keyring_tv_trace_updated_properly(struct aws_array_list *trace, uint32_t flags);

struct raw_rsa_keyring_test_vector {
    enum aws_cryptosdk_rsa_padding_mode rsa_padding_mode;
    enum aws_cryptosdk_alg_id alg;
    const uint8_t *data_key;
    size_t data_key_len;
    const uint8_t *edk_bytes;
    size_t edk_bytes_len;
};
extern struct raw_rsa_keyring_test_vector raw_rsa_keyring_test_vectors[];

struct aws_cryptosdk_edk edk_init(const uint8_t *edk_bytes, size_t edk_len);

struct aws_cryptosdk_edk edk_init_test_vector_idx(int idx);

struct aws_cryptosdk_edk edk_init_test_vector(struct raw_rsa_keyring_test_vector *tv);

#endif  // AWS_CRYPTOSDK_TESTS_LIB_RAW_RSA_KR_TEST_VECTORS_H
