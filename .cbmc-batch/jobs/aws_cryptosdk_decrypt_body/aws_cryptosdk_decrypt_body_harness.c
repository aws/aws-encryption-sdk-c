/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/cipher.h>
#include <make_common_data_structures.h>

void aws_cryptosdk_decrypt_body_harness() {
    /* Non-deterministic inputs. */
    enum aws_cryptosdk_alg_id alg_id;
    struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);
    __CPROVER_assume(aws_cryptosdk_alg_properties_is_valid(props));

    struct aws_byte_buf outp;
    __CPROVER_assume(aws_byte_buf_is_bounded(&outp, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&outp);
    __CPROVER_assume(aws_byte_buf_is_valid(&outp));

    struct aws_byte_cursor inp;
    __CPROVER_assume(aws_byte_cursor_is_bounded(&inp, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(&inp);
    __CPROVER_assume(aws_byte_cursor_is_valid(&inp));

    struct aws_byte_buf message_id;
    __CPROVER_assume(aws_byte_buf_is_bounded(&message_id, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&message_id);
    __CPROVER_assume(aws_byte_buf_is_valid(&message_id));

    uint32_t seqno;

    uint8_t *iv = can_fail_malloc(props->iv_len);
    __CPROVER_assume(iv != NULL);

    struct content_key *content_key;

    /* Need to allocate tag_len bytes for writing the tag */
    uint8_t *tag = can_fail_malloc(props->tag_len);
    __CPROVER_assume(tag != NULL);

    int body_frame_type;

    /* save current state of outp */
    struct aws_byte_cursor old_inp = inp;

    struct aws_byte_buf old_outp = outp;
    struct store_byte_from_buffer old_byte;
    save_byte_from_array(outp.buffer, outp.len, &old_byte);

    struct aws_byte_buf old_message_id = message_id;
    struct store_byte_from_buffer old_message_id_byte;
    save_byte_from_array(message_id.buffer, message_id.len, &old_message_id_byte);
    /* Operation under verification. */
    if (aws_cryptosdk_decrypt_body(props, &outp, &inp, &message_id, seqno, iv, content_key, tag, body_frame_type) ==
        AWS_OP_SUCCESS) {
        assert(inp.len == old_outp.capacity - old_outp.len);
        assert(outp.len >= old_outp.len && outp.len <= old_outp.len + inp.len);
    } else {
        assert(inp.len == old_inp.len);
        assert(outp.len == old_outp.len || outp.len == 0);
    }

    /* Post-conditions. */
    assert(aws_cryptosdk_alg_properties_is_valid(props));
    assert(aws_byte_buf_is_valid(&outp));
    assert(aws_byte_cursor_is_valid(&inp));
    assert(aws_byte_buf_is_valid(&message_id));
    assert_byte_buf_equivalence(&message_id, &old_message_id, &old_message_id_byte);
}