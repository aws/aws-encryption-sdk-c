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

#include <ec_utils.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#include <proof_helpers/nondet.h>
#include <proof_helpers/proof_allocators.h>

/* Abstraction of the EC_GROUP struct */
struct ec_group_st {
    int curve_name;
    point_conversion_form_t asn1_form;
};

/*
 * Description: In order to construct a builtin curve use the function EC_GROUP_new_by_curve_name and provide the nid of
 * the curve to be constructed. Return values: All EC_GROUP_new* functions return a pointer to the newly constructed
 * group, or NULL on error.
 */
EC_GROUP *EC_GROUP_new_by_curve_name(int nid) {
    assert(nid == NID_X9_62_prime256v1 || nid == NID_secp384r1);

    EC_GROUP *group = can_fail_malloc(sizeof(EC_GROUP));

    if (group) {
        group->curve_name = nid;
        group->asn1_form  = POINT_CONVERSION_UNCOMPRESSED;
    }

    return group;
}

/*
 * Description: The functions EC_GROUP_set_point_conversion_form and EC_GROUP_get_point_conversion_form set and get the
 * point_conversion_form for the curve respectively.
 */
void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form) {
    assert(group);
    group->asn1_form = form;
}

/*
 * Description: EC_GROUP_free frees the memory associated with the EC_GROUP. If group is NULL nothing is done.
 */
void EC_GROUP_free(EC_GROUP *group) {
    free(group);
}

struct ec_key_st {
    int references;
    EC_GROUP *group;
    point_conversion_form_t conv_form;
    bool pub_key_is_set;
    bool priv_key_is_set;
};

/*
 * Description: A new EC_KEY with no associated curve can be constructed by calling EC_KEY_new(). The reference count
 * for the newly created EC_KEY is initially set to 1. Return value: EC_KEY_new(), EC_KEY_new_by_curve_name() and
 * EC_KEY_dup() return a pointer to the newly created EC_KEY object, or NULL on error.
 */
EC_KEY *EC_KEY_new() {
    EC_KEY *key = can_fail_malloc(sizeof(EC_KEY));

    if (key) {
        key->references     = 1;
        key->group          = NULL;  // no associated curve
        key->conv_form      = POINT_CONVERSION_UNCOMPRESSED;
        key->pub_key_is_set = false;
    }

    return key;
}

/*
 * Description: The function EC_KEY_set_group() sets the EC_GROUP object for the key.
 * Return values: Returns 1 on success or 0 on error.
 */
int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group) {
    assert(key);

    if (!group || nondet_bool()) return 0;

    EC_GROUP_free(key->group);
    key->group = can_fail_malloc(sizeof(EC_GROUP));

    if (!key->group) return 0;

    *key->group = *group;

    return 1;
}

/*
 * Description: The functions EC_KEY_get_conv_form() and EC_KEY_set_conv_form() get and set the point_conversion_form
 * for the key.
 */
void EC_KEY_set_conv_form(EC_KEY *key, point_conversion_form_t cform) {
    assert(key);
    key->conv_form = cform;
    if (key->group != NULL) EC_GROUP_set_point_conversion_form(key->group, cform);
}

/*
 * Description: The function EC_KEY_set_private_key() sets the private key for the key.
 * Return values: Returns 1 on success or 0 on error.
 */
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv) {
    assert(key);
    assert(prv);

    if (key->group == NULL || nondet_bool()) {
        return 0;
    }

    key->priv_key_is_set = true;
    return 1;
}

/*
 * Description: EC_KEY_up_ref() increments the reference count associated with the EC_KEY object.
 * Return values: EC_KEY_up_ref() returns 1 on success or 0 on error.
 */
int EC_KEY_up_ref(EC_KEY *key) {
    assert(key);

    key->references += 1;
    return 1;  // Can we assume that this never fails?
}

/*
 * Description: Calling EC_KEY_free() decrements the reference count for the EC_KEY object, and if it has dropped to
 * zero then frees the memory associated with it. If key is NULL nothing is done.
 */
void EC_KEY_free(EC_KEY *key) {
    if (key) {
        key->references -= 1;
        if (key->references == 0) {
            EC_GROUP_free(key->group);
            free(key);
        }
    }
}

/** Decodes a ec public key from a octet string.
 *  \param  key  a pointer to a EC_KEY object which should be used
 *  \param  in   memory buffer with the encoded public key
 *  \param  len  length of the encoded public key
 *  \return EC_KEY object with decoded public key or NULL if an error
 *          occurred.
 */
EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len) {
    assert(in);
    assert(*in);
    assert(AWS_MEM_IS_READABLE(*in, len));

    if (!key || !(*key) || !(*key)->group || nondet_bool()) {
        return NULL;
    }

    (*key)->pub_key_is_set = true;

    // o2i_ECPublicKey calls EC_KEY_oct2key, which in some cases sets the conversion form.
    // Can we guarantee that this never happens in our use cases?
    // Any other possible changes to the EC_KEY?

    long offset;
    __CPROVER_assume(0 <= offset && offset <= len);
    *in += offset;
    return *key;
}

/** Encodes a ec public key in an octet string.
 *  \param  key  the EC_KEY object with the public key
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred
 */
int i2o_ECPublicKey(const EC_KEY *key, unsigned char **out) {
    assert(out);           // Assuming that it's always called in ESDK with non-NULL out
    assert(*out == NULL);  // Assuming that it's always called with NULL *out, so buffer needs to be allocated

    if (!key) return 0;

    int buf_len;
    __CPROVER_assume(0 < buf_len);
    *out = can_fail_malloc(buf_len);

    if (*out == NULL) {
        int error_code;
        __CPROVER_assume(error_code <= 0);
        return error_code;
    }

    return buf_len;
}

/* CBMC helper functions */

bool ec_group_is_valid(EC_GROUP *group) {
    return group && (group->curve_name != NID_undef) && (group->asn1_form == POINT_CONVERSION_COMPRESSED);
}

/* Helper function for CBMC proofs: check validity of an EC_KEY. */
bool ec_key_is_valid(EC_KEY *key) {
    return key && (0 < key->references) && ec_group_is_valid(key->group) && (key->group->asn1_form == key->conv_form) &&
           key->pub_key_is_set && key->priv_key_is_set;
}

/* Helper function for CBMC proofs: allocates an EC_KEY nondeterministically. */
EC_KEY *ec_key_nondet_alloc() {
    EC_KEY *key = can_fail_malloc(sizeof(EC_KEY));

    if (key) key->group = can_fail_malloc(sizeof(EC_GROUP));

    return key;
}

/* Helper function for CBMC proofs: returns the reference count. */
int ec_key_get_reference_count(EC_KEY *key) {
    return key ? key->references : 0;
}

/* Helper function for CBMC proofs: returns the group. */
int ec_key_get_group(EC_KEY *key) {
    return key ? key->group : NULL;
}

/* Helper function for CBMC proofs: frees the memory regardless of the reference count. */
void ec_key_unconditional_free(EC_KEY *key) {
    free(key->group);
    free(key);
}
