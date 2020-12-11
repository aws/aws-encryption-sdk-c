/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/hkdf.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/session.h>
#include <make_common_data_structures.h>

void derive_data_key_harness() {
    /* Nondet input */
    struct aws_cryptosdk_session *session         = malloc(sizeof(*session));
    struct aws_cryptosdk_dec_materials *materials = malloc(sizeof(*materials));

    /* Assumptions */
    __CPROVER_assume(session != NULL);
    __CPROVER_assume(aws_cryptosdk_commitment_policy_is_valid(session->commitment_policy));

    session->alg_props = malloc(sizeof(*session->alg_props));
    __CPROVER_assume(session->alg_props != NULL);
    ensure_alg_properties_attempt_allocation(session->alg_props);
    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(session->alg_props));
    __CPROVER_assume(session->alg_props->commitment_len <= sizeof(session->key_commitment_arr));

    __CPROVER_assume(aws_byte_buf_is_bounded(&session->header.message_id, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&session->header.message_id);
    __CPROVER_assume(aws_byte_buf_is_valid(&session->header.message_id));

    __CPROVER_assume(aws_byte_buf_is_bounded(&session->header.alg_suite_data, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&session->header.alg_suite_data);
    __CPROVER_assume(aws_byte_buf_is_valid(&session->header.alg_suite_data));

    __CPROVER_assume(materials != NULL);
    __CPROVER_assume(aws_byte_buf_is_bounded(&materials->unencrypted_data_key, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&materials->unencrypted_data_key);
    __CPROVER_assume(aws_byte_buf_is_valid(&materials->unencrypted_data_key));

    /* Save current state of the data structures */
    struct aws_byte_buf *old_message_id = &session->header.message_id;
    struct store_byte_from_buffer old_byte_from_message_id;
    save_byte_from_array(session->header.message_id.buffer, session->header.message_id.len, &old_byte_from_message_id);

    struct aws_byte_buf *old_alg_suite_data = &session->header.alg_suite_data;
    struct store_byte_from_buffer old_byte_from_alg_suite_data;
    save_byte_from_array(
        session->header.alg_suite_data.buffer, session->header.alg_suite_data.len, &old_byte_from_alg_suite_data);

    struct aws_byte_buf *old_unencrypted_data_key = &materials->unencrypted_data_key;
    struct store_byte_from_buffer old_byte_from_unencrypted_data_key;
    save_byte_from_array(
        materials->unencrypted_data_key.buffer,
        materials->unencrypted_data_key.len,
        &old_byte_from_unencrypted_data_key);

    /* Operation under verification */
    __CPROVER_file_local_session_decrypt_c_derive_data_key(session, materials);

    /* Postconditions */
    assert(aws_cryptosdk_alg_properties_is_valid(session->alg_props));
    assert(aws_byte_buf_is_valid(&session->header.alg_suite_data));
    assert_byte_buf_equivalence(&session->header.alg_suite_data, old_alg_suite_data, &old_byte_from_alg_suite_data);
    assert(aws_byte_buf_is_valid(&session->header.message_id));
    assert_byte_buf_equivalence(&session->header.message_id, old_message_id, &old_byte_from_message_id);
    assert(aws_byte_buf_is_valid(&materials->unencrypted_data_key));
    assert_byte_buf_equivalence(
        &materials->unencrypted_data_key, old_unencrypted_data_key, &old_byte_from_unencrypted_data_key);
}
