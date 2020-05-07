/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/enc_ctx.h>
#include <aws/cryptosdk/private/utils.h>

#include <aws/common/byte_buf.h>
#include <aws/common/common.h>
#include <aws/common/hash_table.h>
#include <aws/common/math.h>

#include <proof_helpers/utils.h>
/**
 * Stub for aws_cryptosdk_enc_ctx_size.
 * This is a pure function, so simply setting these non-det return values is a complete
 * stub for the function's effects.  Not actually calculating the size needed is safe,
 * because this is only ever used to estimate the size for a memory-safe byte-buf.
 */
int aws_cryptosdk_enc_ctx_size(size_t *size, const struct aws_hash_table *enc_ctx) {
    *size = nondet_size_t();
    __CPROVER_assume(*size <= UINT16_MAX);
    return nondet_int();
}
