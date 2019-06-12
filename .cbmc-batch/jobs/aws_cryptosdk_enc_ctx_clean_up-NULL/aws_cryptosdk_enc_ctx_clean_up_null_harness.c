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

#include <aws/common/hash_table.h>
#include <aws/common/private/hash_table_impl.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>

/**
 * Checks aws_cryptosdk_enc_ctx_clean_up for the case where
 * the hash-table has a NULL implementation
 */
void aws_cryptosdk_enc_ctx_clean_up_null_harness() {
    struct aws_hash_table map;
    map.p_impl = NULL;

    aws_cryptosdk_enc_ctx_clean_up(&map);
    assert(map.p_impl == NULL);
}
