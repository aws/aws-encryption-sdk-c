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

#include <openssl/asn1.h>

#include <openssl/bn.h>

#include <make_common_data_structures.h>
#include <proof_helpers/nondet.h>

#include <bn_utils.h>

/* Abstraction of ASN1_STRING data structure */
struct asn1_string_st {
    bool is_valid;
};

/* Could not find OpenSSL documentation */
void ASN1_STRING_clear_free(ASN1_STRING *a) {
    free(a);
}

bool asn1_integer_is_valid(ASN1_INTEGER *ai);

/*
 * Description: ASN1_INTEGER_to_BN() converts ASN1_INTEGER ai into a BIGNUM. If bn is NULL a new BIGNUM structure is
 * returned. If bn is not NULL then the existing structure will be used instead. Return values: ASN1_INTEGER_to_BN() and
 * ASN1_ENUMERATED_to_BN() return a BIGNUM structure of NULL if an error occurs. They can fail if the passed type is
 * incorrect (due to programming error) or due to a memory allocation failure.
 */
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn) {
    assert(asn1_integer_is_valid(ai));
    assert(!bn);  // Assuming is always called with bn == NULL

    BIGNUM *rv = bignum_nondet_alloc();

    __CPROVER_assume(!rv || bignum_is_valid(rv));

    return rv;
}

/*
 * Description: BN_to_ASN1_INTEGER() converts BIGNUM bn to an ASN1_INTEGER. If ai is NULL a new ASN1_INTEGER structure
 * is returned. If ai is not NULL then the existing structure will be used instead. Return value: BN_to_ASN1_INTEGER()
 * returns an ASN1_INTEGER structure respectively or NULL if an error occurs. They will only fail due to a memory
 * allocation error.
 */
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai) {
    assert(bignum_is_valid(bn));
    assert(!ai);  // Assuming is always called with ai == NULL

    ASN1_INTEGER *rv = can_fail_malloc(sizeof(ASN1_INTEGER));

    if (rv) rv->is_valid = true;

    return rv;
}

/*
 * Description: d2i_TYPE() attempts to decode len bytes at *ppin. If successful a pointer to the TYPE structure is
 * returned and *ppin is incremented to the byte following the parsed data. If a is not NULL then a pointer to the
 * returned structure is also written to *a. If an error occurred then NULL is returned. Return values: d2i_TYPE(),
 * d2i_TYPE_bio() and d2i_TYPE_fp() return a valid TYPE structure or NULL if an error occurs. If the "reuse" capability
 * has been used with a valid structure being passed in via a, then the object is not freed in the event of error but
 * may be in a potentially invalid or inconsistent state. Bugs: In some versions of OpenSSL the "reuse" behaviour of
 * d2i_TYPE() when *px is valid is broken and some parts of the reused structure may persist if they are not present in
 * the new one. As a result the use of this "reuse" behaviour is strongly discouraged.
 */
ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, unsigned char **ppin, long length) {
    assert(a);
    assert(*a == NULL);  // Assuming *a is always initialized with NULL, therefore no reuse occurs
    assert(ppin);
    assert(*ppin);
    assert(AWS_MEM_IS_READABLE(*ppin, length));

    *a = can_fail_malloc(sizeof(ASN1_INTEGER));

    /* If *a is not NULL it might be in an invalid state */
    if (*a == NULL || nondet_bool()) {
        return NULL;
    }

    long offset;
    __CPROVER_assume(0 <= offset && offset <= length);
    *ppin += offset;
    (*a)->is_valid = true;
    return *a;
}

/*
 * Description: i2d_TYPE() encodes the structure pointed to by a into DER format. If ppout is not NULL, it writes the
 * DER encoded data to the buffer at *ppout, and increments it to point after the data just written. If the return value
 * is negative an error occurred, otherwise it returns the length of the encoded data. Return values: i2d_TYPE() returns
 * the number of bytes successfully encoded or a negative value if an error occurs.
 */
int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **ppout) {
    assert(asn1_integer_is_valid(a));
    assert(ppout);
    assert(!*ppout);  // Assuming is always called with *ppout == NULL, therefore needs to allocated the buffer

    int buf_size;
    __CPROVER_assume(0 < buf_size);
    *ppout = can_fail_malloc(buf_size);

    if (!*ppout) {
        int error_code;
        __CPROVER_assume(error_code < 0);
        return error_code;
    }

    // Since the buffer is allocated internally, don't need to increment

    return buf_size;
}

/* CBMC helper functions */

bool asn1_integer_is_valid(ASN1_INTEGER *ai) {
    return ai && ai->is_valid;
}
