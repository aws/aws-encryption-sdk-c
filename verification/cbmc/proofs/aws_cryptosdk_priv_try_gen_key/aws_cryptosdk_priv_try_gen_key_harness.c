/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aws/cryptosdk/materials.h>
#include <cbmc_invariants.h>
#include <cipher_openssl.h>
#include <make_common_data_structures.h>
#include <proof_helpers/cryptosdk/make_common_data_structures.h>
#include <proof_helpers/make_common_data_structures.h>

#include <proof_helpers/utils.h>
#include <proof_allocators.h>

#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>

int generate_enc_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_enc_materials **output,
    struct aws_cryptosdk_enc_request *request);

/*
 * This harness is extremely expensive to run so we have stubbed out
 * multiple functions (see Makefile). It also requires a quite specific
 * configuration for the session struct (cmm's vtable must include a
 * pointer to the function declared above, alg_props can be NULL or valid,
 * etc.) so we do not use the session_setup method to initialize it.
 */
void aws_cryptosdk_priv_try_gen_key_harness() {
    /* Nondet Input */
    struct aws_cryptosdk_session *session = malloc(sizeof(*session));

    /* Assumptions */
    __CPROVER_assume(session != NULL);

    /* Set session->cmm */
    const struct aws_cryptosdk_cmm_vt vtable = { .vt_size = sizeof(struct aws_cryptosdk_cmm_vt),
                                                 .name    = ensure_c_str_is_allocated(SIZE_MAX),
                                                 .destroy = nondet_voidp(),
                                                 .generate_enc_materials =
                                                     nondet_bool() ? generate_enc_materials : NULL,
                                                 .decrypt_materials = nondet_voidp() };
    __CPROVER_assume(aws_cryptosdk_cmm_vtable_is_valid(&vtable));

    struct aws_cryptosdk_cmm *cmm = malloc(sizeof(*cmm));
    __CPROVER_assume(cmm);
    cmm->vtable = &vtable;
    __CPROVER_assume(aws_cryptosdk_cmm_base_is_valid(cmm));
    session->cmm = cmm;

    /* session->alg_props can be NULL or valid */
    session->alg_props = ensure_alg_properties_attempt_allocation(MAX_STRING_LEN);
    __CPROVER_assume(IMPLIES(session->alg_props != NULL, aws_cryptosdk_alg_properties_is_valid(session->alg_props)));

    /* Set the session->header */
    struct aws_cryptosdk_hdr *hdr = hdr_setup(MAX_TABLE_SIZE, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE);

    /* The header edk_list should have been cleared earlier.
     * See comment in build_header:
     * "The header should have been cleared earlier, so the materials structure
     * should have zero EDKs" (otherwise we'd need to destroy the old EDKs as well)
     */
    __CPROVER_assume(aws_array_list_length(&hdr->edk_list) == 0);
    session->header = *hdr;

    /* Set session->keyring_trace */
    struct aws_array_list *keyring_trace = malloc(sizeof(*keyring_trace));
    __CPROVER_assume(keyring_trace != NULL);
    __CPROVER_assume(aws_array_list_is_bounded(
        keyring_trace, MAX_TRACE_LIST_ITEMS, sizeof(struct aws_cryptosdk_keyring_trace_record)));
    __CPROVER_assume(keyring_trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(keyring_trace);
    __CPROVER_assume(aws_array_list_is_valid(keyring_trace));
    ensure_trace_has_allocated_records(keyring_trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(keyring_trace));
    session->keyring_trace = *keyring_trace;

    /* Set the allocators */
    session->alloc = can_fail_allocator();
    __CPROVER_assume(aws_allocator_is_valid(session->alloc));
    /* This assumption is needed for build_header */
    session->header.edk_list.alloc = session->alloc;

    __CPROVER_assume(aws_cryptosdk_commitment_policy_is_valid(session->commitment_policy));
    __CPROVER_assume(session->state == ST_GEN_KEY);
    __CPROVER_assume(session->mode == AWS_CRYPTOSDK_ENCRYPT);

    /* session->signctx can be NULL or valid */
    session->signctx = ensure_nondet_sig_ctx_has_allocated_members();
    __CPROVER_assume(IMPLIES(session->signctx != NULL, aws_cryptosdk_sig_ctx_is_valid(session->signctx)));

    /* session->key_commitment must be valid */
    ensure_byte_buf_has_allocated_buffer_member(&session->key_commitment);
    __CPROVER_assume(aws_byte_buf_is_bounded(&session->key_commitment, MAX_BUFFER_SIZE));
    __CPROVER_assume(aws_byte_buf_is_valid(&session->key_commitment));

    /* Save current state of the data structure */
    struct store_byte_from_buffer old_enc_ctx;
    save_byte_from_hash_table(&session->header.enc_ctx, &old_enc_ctx);

    /* Function under verification */
    if (aws_cryptosdk_priv_try_gen_key(session) == AWS_OP_SUCCESS) {
        /* Assertions */
        assert(aws_cryptosdk_session_is_valid(session));
    }
    check_hash_table_unchanged(&session->header.enc_ctx, &old_enc_ctx);
}
