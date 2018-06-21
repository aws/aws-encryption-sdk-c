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

#ifndef AWS_CRYPTOSDK_BUILTIN_PROVIDERS_H
#define AWS_CRYPTOSDK_BUILTIN_PROVIDERS_H

#include <aws/cryptosdk/cipher.h>

/**
 * Internal implementation details of the single MKP and default CMM.
 * This allows us to embed them into the session structure without additional
 * allocation.
 *
 * For ABI compatibility reasons, outside applications and libraries should not
 * use these definitions.
 */

struct default_cmm {
    const struct aws_cryptosdk_cmm_vt * vt;
    struct aws_allocator * alloc;
    struct aws_cryptosdk_mkp * mkp;
};

struct aws_cryptosdk_cmm * aws_cryptosdk_default_cmm_init_inplace(
    struct default_cmm *cmm,
    struct aws_cryptosdk_mkp * mkp
);

struct aws_cryptosdk_single_mkp {
    struct aws_cryptosdk_mkp_vt * vt;
    struct aws_allocator * alloc;
    struct aws_cryptosdk_mk * mk;
};

struct aws_cryptosdk_mkp * aws_cryptosdk_single_mkp_init_inplace(
    struct aws_cryptosdk_single_mkp *mkp,
    struct aws_cryptosdk_mk * mk
);

#endif // AWS_CRYPTOSDK_BUILTIN_PROVIDERS_H
