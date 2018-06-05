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

/**
 * Invalid CMMs for testing virtual function error handling.
 */

#include "bad_cmm.h"

struct bad_cmm {const struct aws_cryptosdk_cmm_vt * vt;};

static bool destroy_succeed_ran = false;

bool zero_size_cmm_did_destroy_vf_run() {return destroy_succeed_ran;}

/**
 * VFs which should never get called because of the failed check on the vt_size field.
 */
void destroy_succeed(struct aws_cryptosdk_cmm * cmm) {
    destroy_succeed_ran = true;
}

int generate_succeed(struct aws_cryptosdk_cmm * cmm,
                     struct aws_cryptosdk_encryption_materials ** output,
                     struct aws_cryptosdk_encryption_request * request) {
    return AWS_OP_SUCCESS;
}

int decrypt_succeed(struct aws_cryptosdk_cmm * cmm,
                    struct aws_cryptosdk_decryption_materials ** output,
                    struct aws_cryptosdk_decryption_request * request) {
    return AWS_OP_SUCCESS;
}

/**
 * A totally correct VT except for the zero size.
 */
static const struct aws_cryptosdk_cmm_vt zero_size_cmm_vt = {
    .vt_size = 0,
    .name = "zero size cmm",
    .destroy = destroy_succeed,
    .generate_encryption_materials = generate_succeed,
    .decrypt_materials = decrypt_succeed
};

static struct bad_cmm zero_size_cmm_singleton = {.vt = &zero_size_cmm_vt};
static struct aws_cryptosdk_cmm * zero_size_cmm = (struct aws_cryptosdk_cmm *) &zero_size_cmm_singleton;

struct aws_cryptosdk_cmm * aws_cryptosdk_zero_size_cmm_new() {return zero_size_cmm;}



static const struct aws_cryptosdk_cmm_vt null_cmm_vt = {
    .vt_size = sizeof(struct aws_cryptosdk_cmm_vt),
    .name = "null cmm",
    .destroy = NULL,
    .generate_encryption_materials = NULL,
    .decrypt_materials = NULL
};

static struct bad_cmm null_cmm_singleton = {.vt = &null_cmm_vt};
static struct aws_cryptosdk_cmm * null_cmm = (struct aws_cryptosdk_cmm *) &null_cmm_singleton;

struct aws_cryptosdk_cmm * aws_cryptosdk_null_cmm_new() {return null_cmm;}
