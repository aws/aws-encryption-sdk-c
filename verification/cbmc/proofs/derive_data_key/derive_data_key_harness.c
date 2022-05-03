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
    /* Setup functions include nondet. allocation and common assumptions */
    struct aws_cryptosdk_session *session =
        session_setup(MAX_TABLE_SIZE, MAX_TRACE_LIST_ITEMS, MAX_EDK_LIST_ITEMS, MAX_BUFFER_SIZE, MAX_STRING_LEN);
    struct aws_cryptosdk_dec_materials *materials =
        dec_materials_setup(MAX_TRACE_LIST_ITEMS, MAX_BUFFER_SIZE, MAX_STRING_LEN);

    /* Assumptions */
    if (session->alg_props == NULL) {
        struct aws_cryptosdk_alg_properties *props = ensure_alg_properties_attempt_allocation(MAX_STRING_LEN);
        __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(props));
        session->alg_props = props;
    }
    __CPROVER_assume(aws_cryptosdk_commitment_policy_is_valid(session->commitment_policy));
    __CPROVER_assume(session->alg_props->commitment_len <= sizeof(session->key_commitment_arr));

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
    int rv = __CPROVER_file_local_session_decrypt_c_derive_data_key(session, materials);

    /* Postconditions */
    if (rv == AWS_OP_ERR) {
        int last_err = aws_last_error();
        if (session->alg_props->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_1_0) {
            if (last_err == AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT) {
                assert(session->header.message_id.len != MSG_ID_LEN);
            }
        } else if (session->alg_props->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_2_0) {
            if (last_err == AWS_CRYPTOSDK_ERR_UNSUPPORTED_FORMAT) {
                assert(
                    session->header.message_id.len != MSG_ID_LEN_V2 ||
                    aws_cryptosdk_which_sha(session->alg_props->alg_id) == AWS_CRYPTOSDK_NOSHA);
            }
        }
    }
    assert(aws_cryptosdk_session_is_valid(session));
    assert(aws_cryptosdk_dec_materials_is_valid(materials));
    assert_byte_buf_equivalence(&session->header.alg_suite_data, old_alg_suite_data, &old_byte_from_alg_suite_data);
    assert_byte_buf_equivalence(&session->header.message_id, old_message_id, &old_byte_from_message_id);
    assert_byte_buf_equivalence(
        &materials->unencrypted_data_key, old_unencrypted_data_key, &old_byte_from_unencrypted_data_key);
}
