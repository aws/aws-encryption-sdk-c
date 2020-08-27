/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <make_common_data_structures.h>
#include <openssl/evp.h>

/* Abstraction of the EVP_PKEY struct */
struct evp_pkey_st {
    int references;
    EC_KEY *ec_key;
};

/**
 * Helper function for CBMC proofs: checks if EVP_PKEY is valid.
 * Use this stub when we are *certain* there is no ec_key associated with the key.
 */
bool evp_pkey_is_valid(EVP_PKEY *pkey) {
    return pkey && (pkey->references > 0) && (pkey->ec_key == NULL);
}
