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

void aws_cryptosdk_encrypt_body_harness() {
    /* Non-deterministic inputs. */
    enum aws_cryptosdk_alg_id alg_id;
    struct aws_byte_buf outp;
    struct aws_byte_cursor inp;
    uint8_t *message_id;
    uint32_t seqno;
    uint8_t *iv;
    struct content_key *content_key;
    uint8_t *tag;
    int body_frame_type;

    /* Assumptions. */
    struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);
    __CPROVER_assume(props != NULL);
    __CPROVER_assume(
        props->impl->cipher_ctor == EVP_aes_128_gcm || props->impl->cipher_ctor == EVP_aes_192_gcm ||
        props->impl->cipher_ctor == EVP_aes_256_gcm);

    __CPROVER_assume(aws_byte_buf_is_bounded(&outp, MAX_BUFFER_SIZE));
    ensure_byte_buf_has_allocated_buffer_member(&outp);
    __CPROVER_assume(aws_byte_buf_is_valid(&outp));

    __CPROVER_assume(aws_byte_cursor_is_bounded(&inp, MAX_BUFFER_SIZE));
    ensure_byte_cursor_has_allocated_buffer_member(&inp);
    __CPROVER_assume(aws_byte_cursor_is_valid(&inp));

    message_id = can_fail_malloc(MAX_BUFFER_SIZE);

    iv = can_fail_malloc(props->iv_len);
    __CPROVER_assume(iv != NULL);

    tag = can_fail_malloc(props->tag_len);

    /* Operation under verification. */
    if (aws_cryptosdk_encrypt_body(props, &outp, &inp, message_id, seqno, iv, content_key, tag, body_frame_type) ==
        AWS_OP_SUCCESS) {
        /* TODO */
    }
}
