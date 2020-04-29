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

#include <limits.h>

#include <bn_utils.h>
#include <ec_utils.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#include <proof_helpers/nondet.h>
#include <proof_helpers/proof_allocators.h>

/* Abstraction of the EC_GROUP struct */
struct ec_group_st {
    int curve_name;
    point_conversion_form_t asn1_form;
    BIGNUM *order;
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
        group->order      = bignum_nondet_alloc();
        __CPROVER_assume(bignum_is_valid(group->order));
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
 * Return values: EC_GROUP_get0_order() returns an internal pointer to the group order.
 */
const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group) {
    assert(ec_group_is_valid(group));
    return group->order;
}

/*
 * Description: EC_GROUP_free frees the memory associated with the EC_GROUP. If group is NULL nothing is done.
 */
void EC_GROUP_free(EC_GROUP *group) {
    if (group) {
        BN_free(group->order);
        free(group);
    }
}

/* Abstraction of the EC_KEY struct */
struct ec_key_st {
    int references;
    EC_GROUP *group;
    point_conversion_form_t conv_form;
    BIGNUM *priv_key;
    bool pub_key_is_set;  // We never have to return a public-key object, so just having this flag is enough
};

/*
 * Description: A new EC_KEY with no associated curve can be constructed by calling EC_KEY_new(). The reference count
 * for the newly created EC_KEY is initially set to 1. Return value: EC_KEY_new(), EC_KEY_new_by_curve_name() and
 * EC_KEY_dup() return a pointer to the newly created EC_KEY object, or NULL on error.
 */
EC_KEY *EC_KEY_new() {
    EC_KEY *key = can_fail_malloc(sizeof(EC_KEY));

    if (key) {
        key->references = 1;
        key->group      = NULL;  // no associated curve
        key->conv_form  = POINT_CONVERSION_UNCOMPRESSED;
        // Can we assume that initially the keys are not set?
        key->priv_key       = NULL;
        key->pub_key_is_set = false;
    }

    return key;
}

/*
 * Description: The function EC_KEY_get0_group() gets the EC_GROUP object for the key.
 * Return values: EC_KEY_get0_group() returns the EC_GROUP associated with the EC_KEY.
 */
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key) {
    assert(ec_key_is_valid(key));
    return key->group;
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

    key->group->curve_name = group->curve_name;
    key->group->asn1_form  = group->asn1_form;
    key->group->order      = BN_dup(group->order);
    __CPROVER_assume(ec_group_is_valid(key->group));  // Since this is the success path, ensure that BN_dup succeeds

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
    assert(bignum_is_valid(prv));

    if (key->group == NULL || nondet_bool()) {
        return 0;
    }

    BN_clear_free(key->priv_key);
    key->priv_key = BN_dup(prv);
    return (key->priv_key == NULL) ? 0 : 1;
}

/*
 * Description: The function EC_KEY_get0_private_key gets the private key for the key.
 * Return values: EC_KEY_get0_private_key() returns the private key associated with the EC_KEY.
 */
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key) {
    assert(key);
    return key->priv_key;
}

/*
 * Description: EC_KEY_generate_key generates a new public and private key for the supplied eckey object. eckey must
 * have an EC_GROUP object associated with it before calling this function. The private key is a random integer (0 <
 * priv_key < order, where order is the order of the EC_GROUP object). The public key is an EC_POINT on the curve
 * calculated by multiplying the generator for the curve by the private key. Return value: Returns 1 on success or 0 on
 * error.
 */
int EC_KEY_generate_key(EC_KEY *key) {
    assert(key);
    assert(ec_group_is_valid(key->group));

    key->priv_key       = bignum_nondet_alloc();
    key->pub_key_is_set = nondet_bool();

    __CPROVER_assume(!key->priv_key || bignum_is_valid(key->priv_key));

    return key->priv_key && key->pub_key_is_set;
}

/*
 * Description: EC_KEY_up_ref() increments the reference count associated with the EC_KEY object.
 * Return values: EC_KEY_up_ref() returns 1 on success or 0 on error.
 */
int EC_KEY_up_ref(EC_KEY *key) {
    assert(ec_key_is_valid(key));

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
            BN_clear_free(key->priv_key);
            free(key);
        }
    }
}

/* Could not find OpenSSL documentation. The following is taken from the header file. */
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
    __CPROVER_assume(0 <= offset && offset <= len);  // public key can be shorter than length
    *in += offset;

    return *key;
}

/* Could not find OpenSSL documentation. The following is taken from the header file. */
/** Encodes a ec public key in an octet string.
 *  \param  key  the EC_KEY object with the public key
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred
 */
int i2o_ECPublicKey(const EC_KEY *key, unsigned char **out) {
    assert(ec_key_is_valid(key));
    assert(out);           // Assuming that it's always called in ESDK with non-NULL out
    assert(*out == NULL);  // Assuming that it's always called with NULL *out, so buffer needs to be allocated

    if (!key) return 0;

    int buf_len;
    __CPROVER_assume(0 < buf_len);
    *out = can_fail_malloc(buf_len);

    if (*out == NULL) {
        int error_code;
        __CPROVER_assume(error_code <= 0);
        return error_code;  // Retuns 0 or negative value on error
    }

    // Should *out be incremented?

    return buf_len;
}

/* Abstraction of ECDSA_SIG struct */
struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};

/*
 * Description: ECDSA_SIG_get0() returns internal pointers the r and s values contained in sig and stores them in *pr
 * and *ps, respectively. The pointer pr or ps can be NULL, in which case the corresponding value is not returned.
 */
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    assert(ecdsa_sig_is_valid(sig));
    assert(pr);
    assert(ps);

    *pr = sig->r;
    *ps = sig->s;
}

/*
 * Description: The r and s values can be set by calling ECDSA_SIG_set0() and passing the new values for r and s as
 * parameters to the function. Calling this function transfers the memory management of the values to the ECDSA_SIG
 * object, and therefore the values that have been passed in should not be freed directly after this function has been
 * called. Return values: ECDSA_SIG_set0() returns 1 on success or 0 on failure.
 */
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
    assert(sig);
    assert(bignum_is_valid(r));
    assert(bignum_is_valid(s));

    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;  // Assuming that should never fail as long as r and s are not NULL
}

/*
 * Description: ECDSA_SIG_free() frees the ECDSA_SIG structure sig.
 */
void ECDSA_SIG_free(ECDSA_SIG *sig) {
    if (sig) {
        BN_clear_free(sig->r);
        BN_clear_free(sig->s);
        free(sig);
    }
}

/*
 * Description: d2i_ECDSA_SIG() decodes a DER encoded ECDSA signature and returns the decoded signature in a newly
 * allocated ECDSA_SIG structure. *sig points to the buffer containing the DER encoded signature of size len.
 */
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len) {
    assert(sig);
    assert(!*sig);
    assert(pp);
    assert(*pp);
    assert(0 <= len);
    assert(AWS_MEM_IS_READABLE(*pp, len));

    *sig = can_fail_malloc(sizeof(ECDSA_SIG));

    if (*sig) {
        (*sig)->r = bignum_nondet_alloc();
        (*sig)->s = bignum_nondet_alloc();
        __CPROVER_assume(ecdsa_sig_is_valid(*sig));  // Assuming that on a success both r and s are initialized
    }

    return *sig;
}

/*
 * Description: i2d_ECDSA_SIG() creates the DER encoding of the ECDSA signature sig and writes the encoded signature to
 * *pp (note: if pp is NULL i2d_ECDSA_SIG() returns the expected length in bytes of the DER encoded signature).
 * i2d_ECDSA_SIG() returns the length of the DER encoded signature (or 0 on error).
 */
int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp) {
    assert(ecdsa_sig_is_valid(sig));
    assert(pp);
    assert(*pp);                                             // Assuming is never called with *pp == NULL
    assert(AWS_MEM_IS_WRITABLE(*pp, max_signature_size()));  // *pp has enough space for the signature

    // Documentation says 0 is returned on error, but OpenSSL implementation returns -1
    // To be safe, we return a number <= 0
    if (nondet_bool()) {
        int error_code;
        __CPROVER_assume(error_code <= 0);
        return error_code;
    }

    int sig_len;
    __CPROVER_assume(0 < sig_len && sig_len <= max_signature_size());
    write_unconstrained_data(*pp, sig_len);
    *pp += sig_len;  // Unclear from the documentation if *pp should really be incremented

    return sig_len;
}

/* CBMC helper functions */

/* Helper function for CBMC proofs: check validity of an EC_GROUP. */
bool ec_group_is_valid(EC_GROUP *group) {
    return group && (group->curve_name != NID_undef) && (group->asn1_form == POINT_CONVERSION_COMPRESSED) &&
           bignum_is_valid(group->order);
}

/* Helper function for CBMC proofs: allocates an EC_GROUP nondeterministically. */
EC_GROUP *ec_group_nondet_alloc() {
    EC_GROUP *group = can_fail_malloc(sizeof(EC_GROUP));

    if (group) group->order = bignum_nondet_alloc();

    return group;
}

/* Helper function for CBMC proofs: check validity of an EC_KEY. */
bool ec_key_is_valid(EC_KEY *key) {
    return key && (0 < key->references) && ec_group_is_valid(key->group) && (key->group->asn1_form == key->conv_form) &&
           key->pub_key_is_set && (!key->priv_key || bignum_is_valid(key->priv_key));
}

/* Helper function for CBMC proofs: allocates an EC_KEY nondeterministically. */
EC_KEY *ec_key_nondet_alloc() {
    EC_KEY *key = can_fail_malloc(sizeof(EC_KEY));

    if (key) {
        key->group    = ec_group_nondet_alloc();
        key->priv_key = bignum_nondet_alloc();
    }

    return key;
}

/* Helper function for CBMC proofs: returns the reference count. */
int ec_key_get_reference_count(EC_KEY *key) {
    return key ? key->references : 0;
}

/* Helper function for CBMC proofs: frees the memory regardless of the reference count. */
void ec_key_unconditional_free(EC_KEY *key) {
    EC_GROUP_free(key->group);
    BN_clear_free(key->priv_key);
    free(key);
}

/* Helper function for CBMC proofs: check validity of an ECDSA_SIG. */
bool ecdsa_sig_is_valid(ECDSA_SIG *sig) {
    return sig && bignum_is_valid(sig->r) && bignum_is_valid(sig->s);
}

static size_t signature_size;

void initialize_max_signature_size() {
    size_t size;
    // At different times, this value is stored in a size_t, a long and an int
    __CPROVER_assume(0 < size && size <= INT_MAX);
    signature_size = size;
}

/* This function returns a fixed nondeterministic value meant to represent the maximum possible size of the DER encoding
 * of a signature. This value is obtained from EVP_PKEY_sign and restricts the size of the buffers in d2i_ECDSA_SIG and
 * i2d_ECDSA_SIG. */
size_t max_signature_size() {
    return signature_size;
}

static size_t derivation_size;

void initialize_max_derivation_size() {
    size_t size;
    // At different times, this value is stored in a size_t, a long and an int
    __CPROVER_assume(0 < size && size <= INT_MAX);
    derivation_size = size;
}

size_t max_derivation_size() {
    return derivation_size;
}

static size_t encryption_size;

void initialize_max_encryption_size() {
    size_t size;
    // At different times, this value is stored in a size_t, a long and an int
    __CPROVER_assume(0 < size && size <= INT_MAX);
    encryption_size = size;
}

size_t max_encryption_size() {
    return encryption_size;
}

static size_t decryption_size;

void initialize_max_decryption_size() {
    size_t size;
    // At different times, this value is stored in a size_t, a long and an int
    __CPROVER_assume(0 < size && size <= INT_MAX);
    encryption_size = size;
}

size_t max_decryption_size() {
    return encryption_size;
}

/* Writes arbitrary data into the buffer out. */
void write_unconstrained_data(unsigned char *out, size_t len) {
    assert(AWS_MEM_IS_WRITABLE(out, len));

    // Currently we ignore the len parameter and just fill the entire buffer with unconstrained data.
    // This is fine because it is strictly more general behavior than writing only len bytes.
    __CPROVER_havoc_object(out);
}
