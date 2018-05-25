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
#include "zero_mkp.h"
#include <aws/cryptosdk/cipher.h> // aws_cryptosdk_secure_zero

/**
 * A degenerate MKP/MK which always returns an all zero data key, just
 * for testing the CMM/MKP/MK infrastructure.
 */

struct zero_mk {const struct aws_cryptosdk_mk_vt * vt;};

/**
 * Sets allocator and buf pointers to NULL so this can be freed safely,
 * and lengths to zero so that this can be serialized correctly.
 */
static inline void zero_edk(struct aws_cryptosdk_edk * edk) {
    aws_cryptosdk_secure_zero(edk, sizeof(struct aws_cryptosdk_edk));
}

static int zero_mk_generate_data_key(struct aws_cryptosdk_mk * mk,
                                     struct aws_byte_buf * unencrypted_data_key,
                                     struct aws_cryptosdk_edk * edk,
                                     struct aws_hash_table * enc_context,
                                     enum aws_cryptosdk_alg_id alg) {
    aws_cryptosdk_secure_zero_buf(unencrypted_data_key);
    zero_edk(edk);
    return AWS_OP_SUCCESS;
}

static int zero_mk_encrypt_data_key(struct aws_cryptosdk_mk * mk,
                                    struct aws_cryptosdk_edk * edk,
                                    const struct aws_byte_buf * unencrypted_data_key,
                                    struct aws_hash_table * enc_context,
                                    enum aws_cryptosdk_alg_id alg) {
    for (size_t byte_idx = 0 ; byte_idx < unencrypted_data_key->len ; ++byte_idx) {
        if (unencrypted_data_key->buffer[byte_idx]) {
            return AWS_OP_ERR;
        }
    }
    zero_edk(edk);
    return AWS_OP_SUCCESS;
}

static void zero_mk_destroy(struct aws_cryptosdk_mk * mk) {}

static const struct aws_cryptosdk_mk_vt zero_mk_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_mk_vt),
    .name = "zero mk",
    .destroy = zero_mk_destroy,
    .generate_data_key = zero_mk_generate_data_key,
    .encrypt_data_key = zero_mk_encrypt_data_key
};

struct zero_mkp {const struct aws_cryptosdk_mkp_vt * vt;};

static struct zero_mk zero_mk_singleton = {.vt = &zero_mk_vt};
static struct aws_cryptosdk_mk * mk = (struct aws_cryptosdk_mk *) &zero_mk_singleton;


static int zero_mkp_append_master_keys(struct aws_cryptosdk_mkp * mkp,
                                       struct aws_array_list * master_keys, // list of (aws_cryptosdk_mk *)
                                       struct aws_hash_table * enc_context) {
    struct zero_mkp * self = (struct zero_mkp *) mkp;

    int ret = aws_array_list_push_back(master_keys, &mk); // copies *address* of the zero MK into the list
    if (ret) { // shouldn't happen if it's a dynamically allocated list
        return aws_raise_error(ret);
    }
    return AWS_OP_SUCCESS;
}

static int zero_mkp_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                     struct aws_byte_buf * unencrypted_data_key,
                                     const struct aws_array_list * encrypted_data_keys,
                                     struct aws_hash_table * enc_context,
                                     enum aws_cryptosdk_alg_id alg) {
    // verify there is at least one EDK with length zero present
    size_t num_keys = encrypted_data_keys->length;
    for (size_t key_idx = 0 ; key_idx < num_keys ; ++key_idx) {
        struct aws_cryptosdk_edk * edk;
        if (aws_array_list_get_at_ptr(encrypted_data_keys, (void **)&edk, 0)) return AWS_OP_ERR;
        if (!edk->enc_data_key.len) {
            aws_cryptosdk_secure_zero_buf(unencrypted_data_key);
            return AWS_OP_SUCCESS;
        }
    }
    return AWS_OP_ERR;
}

static void zero_mkp_destroy(struct aws_cryptosdk_mkp * mkp) {
}

static const struct aws_cryptosdk_mkp_vt zero_mkp_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_mkp_vt),
    .name = "zero mkp",
    .destroy = zero_mkp_destroy,
    .append_master_keys = zero_mkp_append_master_keys,
    .decrypt_data_key = zero_mkp_decrypt_data_key
};

static struct zero_mkp zero_mkp_singleton = {.vt = &zero_mkp_vt};
static struct aws_cryptosdk_mkp * mkp = (struct aws_cryptosdk_mkp *) &zero_mkp_singleton;


struct aws_cryptosdk_mkp * aws_cryptosdk_zero_mkp_new() {return mkp;}
