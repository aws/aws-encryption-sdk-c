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

#include "cache_test_lib.h"
#include "testutil.h"

void gen_enc_materials(struct aws_allocator *alloc, struct aws_cryptosdk_encryption_materials **p_materials, int index, enum aws_cryptosdk_alg_id alg, int n_edks) {
    struct aws_cryptosdk_encryption_materials *materials = *p_materials = aws_cryptosdk_encryption_materials_new(alloc, alg);
    if (!materials) {
        abort();
    }

    byte_buf_printf(&materials->unencrypted_data_key, alloc, "UDK #%d", index);

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg);
    if (props->signature_len) {
        if (aws_cryptosdk_sig_sign_start_keygen(&materials->signctx, alloc, NULL, props)) {
            abort();
        }
    }

    for (int i = 0; i < n_edks; i++) {
        struct aws_cryptosdk_edk edk;
        byte_buf_printf(&edk.enc_data_key, alloc, "EDK #%d.%d", index, i);
        byte_buf_printf(&edk.provider_id, alloc, "Provider ID #%d.%d", index, i);
        byte_buf_printf(&edk.provider_info, alloc, "Provider info #%d.%d", index, i);

        if (aws_array_list_push_back(&materials->encrypted_data_keys, &edk)) {
            abort();
        }
    }
}

bool materials_eq(const struct aws_cryptosdk_encryption_materials *a, const struct aws_cryptosdk_encryption_materials *b) {
    if (a->alg != b->alg) {
        return false;
    }

    if (!!a->signctx != !!b->signctx) {
        return false;
    }

    if (!aws_byte_buf_eq(&a->unencrypted_data_key, &b->unencrypted_data_key)) {
        return false;
    }

    if (aws_array_list_length(&a->encrypted_data_keys) != aws_array_list_length(&b->encrypted_data_keys)) {
        return false;
    }

    size_t len = aws_array_list_length(&a->encrypted_data_keys);
    for (size_t i = 0; i < len; i++) {
        void *vp_a, *vp_b;

        if (aws_array_list_get_at_ptr(&a->encrypted_data_keys, &vp_a, i) ||
            aws_array_list_get_at_ptr(&b->encrypted_data_keys, &vp_b, i)
        ) {
            abort();
        }

        struct aws_cryptosdk_edk *edk_a = vp_a;
        struct aws_cryptosdk_edk *edk_b = vp_b;

        if (!aws_byte_buf_eq(&edk_a->enc_data_key, &edk_b->enc_data_key)) return false;
        if (!aws_byte_buf_eq(&edk_a->provider_id, &edk_b->provider_id)) return false;
        if (!aws_byte_buf_eq(&edk_a->provider_info, &edk_b->provider_info)) return false;
    }

    return true;
}