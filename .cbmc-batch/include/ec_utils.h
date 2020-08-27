/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef EC_UTILS_H
#define EC_UTILS_H

#include <stdbool.h>
#include <stdlib.h>

#include <openssl/ec.h>

bool ec_key_is_valid(EC_KEY *key);

EC_KEY *ec_key_nondet_alloc();

int ec_key_get_reference_count(EC_KEY *key);

void ec_key_unconditional_free(EC_KEY *key);

void initialize_max_signature_size();

size_t max_signature_size();

void initialize_max_derivation_size();

size_t max_derivation_size();

/* This function initializes a fixed nondeterministic value meant to represent the maximum possible amount of encrypted
 * data to be written to the output buffer (see EVP_PKEY_decrypt for an example of its use) */
void initialize_max_encryption_size();

size_t max_encryption_size();

/* This function initializes a fixed nondeterministic value meant to represent the maximum possible amount of decrypted
 * data to be written to the output buffer (see EVP_PKEY_encrypt for an example of its use) */
void initialize_max_decryption_size();

size_t max_decryption_size();

void write_unconstrained_data(unsigned char *out, size_t len);

#endif
