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
#include <aws/common/string.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/default_cmm.h>

#include <assert.h>

#define DEFAULT_ALG ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384

AWS_STATIC_STRING_FROM_LITERAL(EC_PUBLIC_KEY_FIELD, "aws-crypto-public-key");

struct default_cmm {
    struct aws_cryptosdk_cmm base;
    struct aws_allocator *alloc;
    struct aws_cryptosdk_keyring *kr;
    const struct aws_cryptosdk_alg_properties *alg_props;
};

static int default_cmm_generate_enc_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_enc_materials **output,
    struct aws_cryptosdk_enc_request *request) {
    struct aws_cryptosdk_enc_materials *enc_mat      = NULL;
    struct default_cmm *self                         = (struct default_cmm *)cmm;
    const struct aws_cryptosdk_alg_properties *props = self->alg_props;
    struct aws_hash_element *pElement                = NULL;
    *output                                          = NULL;

    aws_hash_table_find(request->enc_ctx, EC_PUBLIC_KEY_FIELD, &pElement);
    if (pElement) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_RESERVED_NAME);
    }

    if (!request->requested_alg) {
        request->requested_alg = props->alg_id;
    }

    enc_mat = aws_cryptosdk_enc_materials_new(request->alloc, request->requested_alg);
    if (!enc_mat) goto err;

    if (props->signature_len) {
        struct aws_string *pubkey = NULL;
        if (aws_cryptosdk_sig_sign_start_keygen(&enc_mat->signctx, request->alloc, &pubkey, props)) {
            goto err;
        }

        if (aws_hash_table_put(request->enc_ctx, EC_PUBLIC_KEY_FIELD, pubkey, NULL)) {
            aws_string_destroy(pubkey);
            goto err;
        }
    }

    if (aws_cryptosdk_keyring_on_encrypt(
            self->kr,
            request->alloc,
            &enc_mat->unencrypted_data_key,
            &enc_mat->keyring_trace,
            &enc_mat->encrypted_data_keys,
            request->enc_ctx,
            request->requested_alg))
        goto err;

    *output = enc_mat;
    return AWS_OP_SUCCESS;

err:
    aws_cryptosdk_enc_materials_destroy(enc_mat);
    return AWS_OP_ERR;
}

static int default_cmm_decrypt_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_dec_materials **output,
    struct aws_cryptosdk_dec_request *request) {
    struct aws_cryptosdk_dec_materials *dec_mat;
    struct default_cmm *self = (struct default_cmm *)cmm;

    dec_mat = aws_cryptosdk_dec_materials_new(request->alloc, request->alg);
    if (!dec_mat) goto err;

    if (aws_cryptosdk_keyring_on_decrypt(
            self->kr,
            request->alloc,
            &dec_mat->unencrypted_data_key,
            &dec_mat->keyring_trace,
            &request->encrypted_data_keys,
            request->enc_ctx,
            request->alg))
        goto err;

    if (!dec_mat->unencrypted_data_key.buffer) {
        aws_raise_error(AWS_CRYPTOSDK_ERR_CANNOT_DECRYPT);
        goto err;
    }

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(request->alg);
    if (props->signature_len) {
        struct aws_hash_element *pElement = NULL;

        if (aws_hash_table_find(request->enc_ctx, EC_PUBLIC_KEY_FIELD, &pElement) || !pElement || !pElement->key) {
            aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
            goto err;
        }

        if (aws_cryptosdk_sig_verify_start(&dec_mat->signctx, request->alloc, pElement->value, props)) {
            goto err;
        }
    }

    *output = dec_mat;
    return AWS_OP_SUCCESS;

err:
    *output = NULL;
    aws_cryptosdk_dec_materials_destroy(dec_mat);
    return AWS_OP_ERR;
}

static void default_cmm_destroy(struct aws_cryptosdk_cmm *cmm) {
    struct default_cmm *self = (struct default_cmm *)cmm;
    aws_cryptosdk_keyring_release(self->kr);
    aws_mem_release(self->alloc, self);
}

static const struct aws_cryptosdk_cmm_vt default_cmm_vt = { .vt_size = sizeof(struct aws_cryptosdk_cmm_vt),
                                                            .name    = "default cmm",
                                                            .destroy = default_cmm_destroy,
                                                            .generate_enc_materials =
                                                                default_cmm_generate_enc_materials,
                                                            .decrypt_materials = default_cmm_decrypt_materials };

struct aws_cryptosdk_cmm *aws_cryptosdk_default_cmm_new(struct aws_allocator *alloc, struct aws_cryptosdk_keyring *kr) {
    struct default_cmm *cmm;
    cmm = aws_mem_acquire(alloc, sizeof(struct default_cmm));
    if (!cmm) return NULL;

    aws_cryptosdk_cmm_base_init(&cmm->base, &default_cmm_vt);

    cmm->alloc = alloc;
    cmm->kr    = aws_cryptosdk_keyring_retain(kr);

    aws_cryptosdk_default_cmm_set_alg_id((struct aws_cryptosdk_cmm *)cmm, DEFAULT_ALG);

    return (struct aws_cryptosdk_cmm *)cmm;
}

int aws_cryptosdk_default_cmm_set_alg_id(struct aws_cryptosdk_cmm *cmm, enum aws_cryptosdk_alg_id alg_id) {
    struct default_cmm *self                         = (struct default_cmm *)cmm;
    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    assert(self->base.vtable == &default_cmm_vt);

    if (!props) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT);
    }

    self->alg_props = props;

    return AWS_OP_SUCCESS;
}
