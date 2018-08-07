
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

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/session.h>
#include <aws/cryptosdk/private/framefmt.h>
#include <aws/common/byte_buf.h>
#include <aws/common/string.h>

/** Session decrypt path routines **/

static int fill_request(
    struct aws_hash_table *enc_context,
    struct aws_cryptosdk_decryption_request *request,
    struct aws_cryptosdk_session *session
) {
    request->alloc = session->alloc;
    request->alg = session->alg_props->alg_id;

    if (aws_array_list_init_dynamic(
        &request->encrypted_data_keys,
        session->alloc,
        session->header.edk_count,
        sizeof(struct aws_cryptosdk_edk)
    )) {
        return AWS_OP_ERR;
    }

    if (aws_hash_table_init(enc_context, session->alloc, session->header.aad_count,
        aws_hash_string, aws_string_eq,
        aws_string_destroy, aws_string_destroy
    )) {
        aws_array_list_clean_up(&request->encrypted_data_keys);
        return AWS_OP_ERR;
    }

    request->enc_context = enc_context;

    for (size_t i = 0; i < session->header.edk_count; i++) {
        if (aws_array_list_push_back(&request->encrypted_data_keys, &session->header.edk_tbl[i])) return AWS_OP_ERR;
    }

    for (size_t i = 0; i < session->header.aad_count; i++) {
        const struct aws_string *key = NULL, *value = NULL;
        const struct aws_cryptosdk_hdr_aad *aad = &session->header.aad_tbl[i];


        key = aws_string_new_from_array(session->alloc, aad->key.buffer, aad->key.len);
        value = aws_string_new_from_array(session->alloc, aad->value.buffer, aad->value.len);

        struct aws_hash_element *pElem;

        if (!key || !value || aws_hash_table_create(enc_context, (void *)key, &pElem, NULL)) {
            aws_string_destroy((struct aws_string *)key);
            aws_string_destroy((struct aws_string *)value);

            return aws_raise_error(AWS_ERROR_OOM);
        }

        pElem->value = (void *)value;
    }

    return AWS_OP_SUCCESS;
}

static int derive_data_key(
    struct aws_cryptosdk_session *session,
    struct aws_cryptosdk_decryption_materials *materials
) {
    if (materials->unencrypted_data_key.len != session->alg_props->data_key_len) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_CRYPTO_UNKNOWN);
    }

    // TODO - eliminate the struct data_key type and use the unencrypted_data_key buffer directly
    struct data_key data_key = { { 0 } };
    memcpy(&data_key.keybuf, materials->unencrypted_data_key.buffer, materials->unencrypted_data_key.len);

    return aws_cryptosdk_derive_key(
        session->alg_props,
        &session->content_key,
        &data_key,
        session->header.message_id
    );
}

static int validate_header(struct aws_cryptosdk_session *session) {
    // Perform header validation
    int header_size = aws_cryptosdk_hdr_size(&session->header);
    size_t authtag_len = session->alg_props->tag_len + session->alg_props->iv_len;

    if (header_size - session->header.auth_len != authtag_len) {
        // The authenticated length field is wrong.
        // XXX: This is a computed field, can this actually fail in practice?
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    struct aws_byte_buf authtag = { .buffer = session->header_copy + session->header.auth_len, .len = authtag_len };
    struct aws_byte_buf headerbytebuf = { .buffer = session->header_copy, .len = session->header.auth_len };

    return aws_cryptosdk_verify_header(session->alg_props, &session->content_key, &authtag, &headerbytebuf);
}

int unwrap_keys(
    struct aws_cryptosdk_session * restrict session
) {
    struct aws_hash_table enc_context;
    struct aws_cryptosdk_decryption_request request;
    struct aws_cryptosdk_decryption_materials *materials = NULL;

    session->alg_props = aws_cryptosdk_alg_props(session->header.alg_id);

    if (!session->alg_props) {
        // Unknown algorithm
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    if (fill_request(&enc_context, &request, session)) return AWS_OP_ERR;
    int rv = AWS_OP_ERR;

    if (aws_cryptosdk_cmm_decrypt_materials(session->cmm, &materials, &request)) goto out;
    if (derive_data_key(session, materials)) goto out;
    if (validate_header(session)) goto out;

    session->frame_seqno = 1;
    session->frame_size = session->header.frame_len;
    session_change_state(session, ST_DECRYPT_BODY);

    rv = AWS_OP_SUCCESS;
out:
    if (materials) aws_cryptosdk_decryption_materials_destroy(materials);
    aws_array_list_clean_up(&request.encrypted_data_keys);
    aws_hash_table_clean_up(&enc_context);

    return rv;
}

int try_parse_header(
    struct aws_cryptosdk_session * AWS_RESTRICT session,
    struct aws_byte_cursor * AWS_RESTRICT input
) {
    int rv = aws_cryptosdk_hdr_parse_init(session->alloc, &session->header, input->ptr, input->len);

    if (rv != AWS_OP_SUCCESS) {
        if (aws_last_error() == AWS_ERROR_SHORT_BUFFER) {
            if (input->len >= session->input_size_estimate) {
                session->input_size_estimate = input->len + 128;
                if (session->input_size_estimate < input->len) {
                    // overflow
                    session->input_size_estimate = (size_t)-1;
                }
            }
            session->output_size_estimate = 0;
            return AWS_OP_SUCCESS; // suppress this error
        }
        return rv;
    }

    session->header_size = aws_cryptosdk_hdr_size(&session->header);
    session->header_copy = aws_mem_acquire(session->alloc, session->header_size);

    if (!session->header_copy) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    memcpy(session->header_copy, input->ptr, session->header_size);

    aws_byte_cursor_advance(input, session->header_size);

    session_change_state(session, ST_UNWRAP_KEY);

    return unwrap_keys(session);
}

int try_decrypt_body(
    struct aws_cryptosdk_session * AWS_RESTRICT session,
    struct aws_byte_cursor * AWS_RESTRICT poutput,
    struct aws_byte_cursor * AWS_RESTRICT pinput
) {
    struct aws_cryptosdk_frame frame;
    // We'll save the original cursor state; if we don't have enough plaintext buffer we'll
    // need to roll back and un-consume the ciphertext.
    struct aws_byte_cursor input_rollback = *pinput;

    size_t ciphertext_size;
    size_t plaintext_size;

    if (aws_cryptosdk_deserialize_frame(&frame, &ciphertext_size, &plaintext_size,
            pinput, session->alg_props, session->frame_size)) {
        session->output_size_estimate = plaintext_size;
        session->input_size_estimate = ciphertext_size;
        if (aws_last_error() == AWS_ERROR_SHORT_BUFFER) {
            // Not actually an error. We've updated the estimates, so move on.
            return AWS_OP_SUCCESS;
        } else {
            // Frame format was malformed. Propagate the error up the chain.
            return AWS_OP_ERR;
        }
    }

    // The frame is structurally sound. Now we just need to do some validation of its
    // contents and decrypt.

    if (session->frame_seqno != frame.sequence_number) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    // Before we go further, do we have enough room to place the plaintext?
    struct aws_byte_cursor output = aws_byte_cursor_advance_nospec(poutput, plaintext_size);
    if (!output.ptr) {
        *pinput = input_rollback;
        // No progress due to not enough plaintext output space.
        return AWS_OP_SUCCESS;
    }

    // We have everything we need, try to decrypt
    int rv = aws_cryptosdk_decrypt_body(
        session->alg_props, &output, &frame.ciphertext, session->header.message_id, session->frame_seqno,
        frame.iv.ptr, &session->content_key, frame.authtag.ptr, frame.type
    );

    if (rv == AWS_ERROR_SUCCESS) {
        session->frame_seqno++;

        if (frame.type != FRAME_TYPE_FRAME) {
            session_change_state(session, ST_CHECK_TRAILER);
        }

        return rv;
    }

    // An error was encountered; the top level loop will transition to the error state
    return rv;
}

