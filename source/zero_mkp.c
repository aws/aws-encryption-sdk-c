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
#include <aws/cryptosdk/zero_mkp.h>
#include <aws/cryptosdk/zero_mk.h>

/**
 * A degenerate Master Key Provider which always returns an all zero data key, just
 * for testing the CMM/MKP/MK infrastructure.
 */

struct zero_mkp {
    const struct aws_cryptosdk_mkp_vt * vt;
    struct aws_allocator * alloc;
};

static struct aws_cryptosdk_mk * zero_mk_singleton = NULL;

static int zero_mkp_append_master_keys(struct aws_cryptosdk_mkp * mkp,
                                       struct aws_array_list * master_keys, // list of (aws_cryptosdk_mk *)
                                       struct aws_hash_table * enc_context) {
    struct zero_mkp * self = (struct zero_mkp *) mkp;

    if (!zero_mk_singleton) {
        zero_mk_singleton = aws_cryptosdk_zero_mk_new(self->alloc);
        if (!zero_mk_singleton) {
            return aws_raise_error(AWS_ERROR_OOM);
        }
    }

    int ret = aws_array_list_push_back(master_keys, &zero_mk_singleton); // copies *address* of the zero MK into the list
    if (ret) { // shouldn't happen if it's a dynamically allocated list
        return aws_raise_error(ret);
    }
    return AWS_OP_SUCCESS;
}

static int zero_mkp_decrypt_data_key(struct aws_cryptosdk_mkp * mkp,
                                     struct aws_cryptosdk_data_key * output,
                                     const struct aws_array_list * encrypted_data_keys,
                                     struct aws_hash_table * enc_context) {
    aws_cryptosdk_secure_zero(output->keybuf, MAX_DATA_KEY_SIZE);
    return AWS_OP_SUCCESS;
}

static void zero_mkp_destroy(struct aws_cryptosdk_mkp * mkp) {
    if (zero_mk_singleton) {
        aws_cryptosdk_mk_destroy(zero_mk_singleton);
    }

    struct zero_mkp * self = (struct zero_mkp *) mkp;
    self->alloc->mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_mkp_vt zero_mkp_vt = {
    sizeof(struct aws_cryptosdk_mkp_vt),
    "zero mkp",
    zero_mkp_destroy,
    zero_mkp_append_master_keys,
    zero_mkp_decrypt_data_key
};

struct aws_cryptosdk_mkp * aws_cryptosdk_zero_mkp_new(struct aws_allocator * alloc) {
    struct zero_mkp * mkp = alloc->mem_acquire(alloc, sizeof(struct zero_mkp));
    if (!mkp) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }
    mkp->vt = &zero_mkp_vt;
    mkp->alloc = alloc;
    return (struct aws_cryptosdk_mkp *) mkp;
}
