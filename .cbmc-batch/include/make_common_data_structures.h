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

#include <aws/common/atomics.h>
#include <aws/common/common.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>
#include <stdint.h>
#include <stdlib.h>

void ensure_alg_properties_attempt_allocation(struct aws_cryptosdk_alg_properties *const alg_props);

/* Allocates the members of the context and ensures that internal pointers are pointing to the correct objects. */
void ensure_md_context_has_allocated_members(struct aws_cryptosdk_md_context *ctx);

/* Allocates the members of the context and ensures that internal pointers are pointing to the correct objects. */
void ensure_sig_ctx_has_allocated_members(struct aws_cryptosdk_sig_ctx *ctx);

bool aws_cryptosdk_edk_list_is_bounded(
    const struct aws_array_list *const list, const size_t max_initial_item_allocation);
bool aws_cryptosdk_edk_list_elements_are_bounded(const struct aws_array_list *const list, const size_t max_item_size);
void ensure_cryptosdk_edk_list_has_allocated_list(struct aws_array_list *list);
void ensure_cryptosdk_edk_list_has_allocated_list_elements(struct aws_array_list *list);

/* Makes internal function from cipher.c accessible for CBMC */
enum aws_cryptosdk_sha_version aws_cryptosdk_which_sha(enum aws_cryptosdk_alg_id alg_id);

void ensure_record_has_allocated_members(struct aws_cryptosdk_keyring_trace_record *record, size_t max_len);
void ensure_trace_has_allocated_records(struct aws_array_list *trace, size_t max_len);

/* Non-deterministically allocates a aws_cryptosdk_keyring structure */
void ensure_cryptosdk_keyring_has_allocated_members(
    struct aws_cryptosdk_keyring *keyring, const struct aws_cryptosdk_keyring_vt *vtable);
