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

#include <aws/cryptosdk/private/cipher.h>
#include <openssl/evp.h>
#include "proof_helpers.h"

#define MSG_ID_LEN 16

const EVP_MD *nondet_EVP_MD_ptr(void);
const EVP_CIPHER *nondet_EVP_CIPHER_ptr(void);

struct aws_cryptosdk_alg_impl {
    const EVP_MD *(*md_ctor)(void);
    const EVP_CIPHER *(*cipher_ctor)(void);
};

void aws_cryptosdk_derive_key_verify(void) {
    struct aws_cryptosdk_alg_properties *props;
    struct content_key *content_key;
    struct data_key *data_key;
    uint8_t *message_id;
    ASSUME_VALID_MEMORY(props);
    props->impl = malloc(sizeof(&nondet_EVP_MD_ptr) + sizeof(&nondet_EVP_CIPHER_ptr));

    props->impl->md_ctor     = NULL;
    props->impl->cipher_ctor = NULL;
    if (nondet_int()) props->impl->md_ctor = &nondet_EVP_MD_ptr;
    if (nondet_int()) props->impl->cipher_ctor = &nondet_EVP_CIPHER_ptr;

    __CPROVER_assume(props->data_key_len <= MAX_DATA_KEY_SIZE);

    ASSUME_VALID_MEMORY(content_key);
    ASSUME_VALID_MEMORY(data_key);
    ASSUME_VALID_MEMORY_COUNT(message_id, MSG_ID_LEN);

    aws_cryptosdk_derive_key(props, content_key, data_key, message_id);
}
