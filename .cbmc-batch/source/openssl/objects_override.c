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

#include <assert.h>
#include <openssl/objects.h>
#include <proof_helpers/nondet.h>
#include <string.h>

/*
 * Description: OBJ_txt2nid() returns NID corresponding to text string <s>. s can be a long name, a short name or the
 * numerical representation of an object. Return values: OBJ_txt2nid() returns a NID or NID_undef on error.
 */
int OBJ_txt2nid(const char *s) {
    // Currently these are the only values used in the ESDK
    if (!s) {
        return NID_undef;
    } else if (strcmp(s, "prime256v1") == 0) {
        return NID_X9_62_prime256v1;
    } else if (strcmp(s, "secp384r1") == 0) {
        return NID_secp384r1;
    } else {
        __CPROVER_assert(0, "s had unexpected value");
    }
    return nondet_int();
}
