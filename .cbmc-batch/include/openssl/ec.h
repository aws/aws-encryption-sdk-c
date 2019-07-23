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

#include <openssl/objects.h>
#include <openssl/ossl_typ.h>

/** Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y) */
typedef enum {
    /** the point is encoded as z||x, where the octet z specifies
     *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_COMPRESSED = 2,
    /** the point is encoded as z||x||y, where z is the octet 0x04  */
    POINT_CONVERSION_UNCOMPRESSED = 4,
    /** the point is encoded as z||x||y, where the octet z specifies
     *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef struct ec_group_st EC_GROUP;

EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form);
void EC_GROUP_free(EC_GROUP *group);

typedef struct ECDSA_SIG_st ECDSA_SIG;

EC_KEY *EC_KEY_new(void);
int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform);
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
int EC_KEY_up_ref(EC_KEY *r);
void EC_KEY_free(EC_KEY *key);

EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len);
int i2o_ECPublicKey(EC_KEY *key, unsigned char **out);
