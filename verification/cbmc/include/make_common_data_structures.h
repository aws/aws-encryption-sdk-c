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
#include <aws/cryptosdk/private/header.h>
#include <proof_helpers/make_common_data_structures.h>
#include <proof_helpers/proof_allocators.h>
#include <proof_helpers/utils.h>
#include <stdint.h>
#include <stdlib.h>

/* Allocates alg_properties members and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_alg_properties *ensure_alg_properties_attempt_allocation(const size_t max_len);

/* Ensures data_key structures are properly allocated. */
struct data_key *ensure_data_key_attempt_allocation();

/* Ensures content_key structures are properly allocated. */
struct content_key *ensure_content_key_attempt_allocation();

/* Allocates the members of the context and ensures that internal pointers are pointing to the correct objects. */
void ensure_md_context_has_allocated_members(struct aws_cryptosdk_md_context *ctx);

/* Allocates the members of the sig context and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_sig_ctx *ensure_nondet_sig_ctx_has_allocated_members();

bool aws_cryptosdk_edk_list_is_bounded(
    const struct aws_array_list *const list, const size_t max_initial_item_allocation);
bool aws_cryptosdk_edk_list_elements_are_bounded(const struct aws_array_list *const list, const size_t max_item_size);
void ensure_cryptosdk_edk_list_has_allocated_list(struct aws_array_list *list);
void ensure_cryptosdk_edk_list_has_allocated_list_elements(struct aws_array_list *list);

/* Allocates the members of the header and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_hdr *ensure_nondet_hdr_has_allocated_members(const size_t max_table_size);

/* Determines if the members of the header are bounded. */
bool aws_cryptosdk_hdr_members_are_bounded(
    const struct aws_cryptosdk_hdr *hdr, const size_t max_edk_item_size, const size_t max_item_size);

/* Allocates and ensures properties of the members of the header. The properties ensured are :
 * Header is either NULL or the internal pointers are pointing to the correct object.
 * The members of the header are bounded.
 * The hdr->edk_list has allocated list elements.
 * The hdr->enc_ctx has valid destory functions.
 * The hdr is non-NULL and each field satisfies the validity properties of its data structure. */
struct aws_cryptosdk_hdr *hdr_setup(
    const size_t max_table_size, const size_t max_edk_item_size, const size_t max_item_size);

/* Makes internal function from cipher.c accessible for CBMC */
enum aws_cryptosdk_sha_version aws_cryptosdk_which_sha(enum aws_cryptosdk_alg_id alg_id);

void ensure_record_has_allocated_members(struct aws_cryptosdk_keyring_trace_record *record, size_t max_len);
void ensure_trace_has_allocated_records(struct aws_array_list *trace, size_t max_len);

/* Non-deterministically allocates a aws_cryptosdk_keyring structure */
void ensure_cryptosdk_keyring_has_allocated_members(
    struct aws_cryptosdk_keyring *keyring, const struct aws_cryptosdk_keyring_vt *vtable);
/* Non-deterministically allocates a aws_cryptosdk_keyring_vt structure with a valid name*/
void ensure_nondet_allocate_keyring_vtable_members(struct aws_cryptosdk_keyring_vt *vtable, size_t max_len);
/* Non-deterministically allocates a aws_cryptosdk_cmm_vt structure with a valid name*/
void ensure_nondet_allocate_cmm_vtable_members(struct aws_cryptosdk_cmm_vt *vtable, size_t max_len);

/* Allocates cmm_vt members and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_cmm_vt *ensure_cmm_vt_attempt_allocation(const size_t max_len);

/* Allocates cmm members and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_cmm *ensure_cmm_attempt_allocation(const size_t max_len);

/* Allocates session members and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_session *ensure_nondet_session_has_allocated_members(size_t max_len);

bool aws_cryptosdk_session_members_are_bounded(
    const struct aws_cryptosdk_session *session,
    const size_t max_trace_items,
    const size_t max_edk_item_size,
    const size_t max_item_size);

struct aws_cryptosdk_session *session_setup(
    const size_t max_table_size,
    const size_t max_trace_items,
    const size_t max_edk_item_size,
    const size_t max_item_size,
    const size_t max_len);

/* Allocates dec_materials members and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_dec_materials *ensure_dec_materials_attempt_allocation();

bool aws_cryptosdk_dec_materials_members_are_bounded(
    const struct aws_cryptosdk_dec_materials *materials, const size_t max_trace_items, const size_t max_item_size);

struct aws_cryptosdk_dec_materials *dec_materials_setup(
    const size_t max_trace_items, const size_t max_item_size, const size_t max_len);

/* Allocates the members of the enc_request and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_enc_request *ensure_enc_request_attempt_allocation(const size_t max_table_size);

/* Allocates the members of the default_cmm and ensures that internal pointers are pointing to the correct objects. */
struct aws_cryptosdk_cmm *ensure_default_cmm_attempt_allocation(struct aws_cryptosdk_keyring *keyring);
