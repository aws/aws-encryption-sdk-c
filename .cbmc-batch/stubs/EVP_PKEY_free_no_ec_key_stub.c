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
 * Description: EVP_PKEY_free() decrements the reference count of key and, if the reference count is zero, frees it up.
 * If key is NULL, nothing is done.
 * Use this stub when we are *certain* there is no ec_key associated with the key.
 */
void EVP_PKEY_free(EVP_PKEY *pkey) {
    if (pkey) {
        pkey->references -= 1;
        if (pkey->references == 0) {
            assert(!pkey->ec_key);
            free(pkey);
        }
    }
}
