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
#include <string.h> // memcpy
#include <aws/cryptosdk/private/header.h>
#include <aws/cryptosdk/private/compiler.h>
#include <aws/cryptosdk/private/enc_context.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/error.h>
#include <aws/common/byte_buf.h>
#include <aws/common/string.h>
#include <aws/common/math.h>

static int aws_cryptosdk_algorithm_is_known(uint16_t alg_id) {
    switch (alg_id) {
        case AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384:
        case AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384:
        case AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256:
        case AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE:
        case AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE:
        case AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE:
        case AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE:
        case AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE:
        case AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE:
            return 1;
        default:
            return 0;
    }
}

int aws_cryptosdk_algorithm_taglen(uint16_t alg_id) {
    if (aws_cryptosdk_algorithm_is_known(alg_id)) {
        // all known algorithms have a tag length of 16 bytes
        return 16;
    }

    return -1;
}

int aws_cryptosdk_algorithm_ivlen(uint16_t alg_id) {
    if (aws_cryptosdk_algorithm_is_known(alg_id)) {
        // all known algorithms have an IV length of 12 bytes
        return 12;
    }

    return -1;
}


static int is_known_type(uint8_t content_type) {
    switch (content_type) {
        case AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED:
        case AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED:
            return 1;
        default:
            return 0;
    }
}

int aws_cryptosdk_hdr_init(struct aws_cryptosdk_hdr *hdr, struct aws_allocator *alloc) {
    aws_secure_zero(hdr, sizeof(*hdr));

    if (aws_cryptosdk_enc_context_init(alloc, &hdr->enc_context)) {
        return AWS_OP_ERR;
    }

    if (aws_cryptosdk_edk_list_init(alloc, &hdr->edk_list)) {
        aws_cryptosdk_enc_context_clean_up(&hdr->enc_context);
        return AWS_OP_ERR;
    }

    hdr->alloc = alloc;

    return AWS_OP_SUCCESS;
}

void aws_cryptosdk_hdr_clear(struct aws_cryptosdk_hdr *hdr) {
    /* hdr->alloc is preserved */
    hdr->alg_id = 0;
    hdr->frame_len = 0;

    aws_byte_buf_clean_up(&hdr->iv);
    aws_byte_buf_clean_up(&hdr->auth_tag);

    memset(&hdr->message_id, 0, sizeof(hdr->message_id));

    aws_cryptosdk_edk_list_clear(&hdr->edk_list);
    aws_cryptosdk_enc_context_clear(&hdr->enc_context);

    hdr->auth_len = 0;
}

void aws_cryptosdk_hdr_clean_up(struct aws_cryptosdk_hdr *hdr) {
    if (!hdr->alloc) {
        // Idempotent cleanup
        return;
    }

    aws_byte_buf_clean_up(&hdr->iv);
    aws_byte_buf_clean_up(&hdr->auth_tag);

    aws_cryptosdk_edk_list_clean_up(&hdr->edk_list);
    aws_cryptosdk_enc_context_clean_up(&hdr->enc_context);

    aws_secure_zero(hdr, sizeof(*hdr));
}

static inline int parse_edk(struct aws_allocator *allocator, struct aws_cryptosdk_edk *edk, struct aws_byte_cursor *cur) {
    uint16_t field_len;

    memset(edk, 0, sizeof(*edk));

    if (!aws_byte_cursor_read_be16(cur, &field_len)) goto SHORT_BUF;
    if (aws_byte_buf_init(allocator, &edk->provider_id, field_len)) goto MEM_ERR;
    if (!aws_byte_cursor_read_and_fill_buffer(cur, &edk->provider_id)) goto SHORT_BUF;

    if (!aws_byte_cursor_read_be16(cur, &field_len)) goto SHORT_BUF;
    if (aws_byte_buf_init(allocator, &edk->provider_info, field_len)) goto MEM_ERR;
    if (!aws_byte_cursor_read_and_fill_buffer(cur, &edk->provider_info)) goto SHORT_BUF;

    if (!aws_byte_cursor_read_be16(cur, &field_len)) goto SHORT_BUF;
    if (aws_byte_buf_init(allocator, &edk->enc_data_key, field_len)) goto MEM_ERR;
    if (!aws_byte_cursor_read_and_fill_buffer(cur, &edk->enc_data_key)) goto SHORT_BUF;

    return AWS_OP_SUCCESS;

SHORT_BUF:
    aws_cryptosdk_edk_clean_up(edk);
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
MEM_ERR:
    aws_cryptosdk_edk_clean_up(edk);
    // The _init function should have already raised an AWS_ERROR_OOM
    return AWS_OP_ERR;
}

int aws_cryptosdk_hdr_parse(struct aws_cryptosdk_hdr *hdr, struct aws_byte_cursor *pcursor) {
    struct aws_byte_cursor cur = *pcursor;

    aws_cryptosdk_hdr_clear(hdr);

    uint8_t bytefield;
    if (!aws_byte_cursor_read_u8(&cur, &bytefield)) goto SHORT_BUF;
    if (aws_cryptosdk_unlikely(bytefield != AWS_CRYPTOSDK_HEADER_VERSION_1_0)) goto PARSE_ERR;

    if (!aws_byte_cursor_read_u8(&cur, &bytefield)) goto SHORT_BUF;
    if (aws_cryptosdk_unlikely(bytefield != AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED)) goto PARSE_ERR;

    uint16_t alg_id;
    if (!aws_byte_cursor_read_be16(&cur, &alg_id)) goto SHORT_BUF;
    if (aws_cryptosdk_unlikely(!aws_cryptosdk_algorithm_is_known(alg_id))) goto PARSE_ERR;
    hdr->alg_id = alg_id;

    if (!aws_byte_cursor_read(&cur, hdr->message_id, MESSAGE_ID_LEN)) goto SHORT_BUF;

    uint16_t aad_len;
    if (!aws_byte_cursor_read_be16(&cur, &aad_len)) goto SHORT_BUF;

    if (aad_len) {
        struct aws_byte_cursor aad = aws_byte_cursor_advance_nospec(&cur, aad_len);

        // Note that, even if this fails with SHORT_BUF, we report a parse error, since we know we
        // have enough data (according to the aad length field).
        if (aws_cryptosdk_context_deserialize(hdr->alloc, &hdr->enc_context, &aad)) goto PARSE_ERR;
        if (aad.len) {
            // trailing garbage after the aad block
            goto PARSE_ERR;
        }
    }

    uint16_t edk_count;
    if (!aws_byte_cursor_read_be16(&cur, &edk_count)) goto SHORT_BUF;
    if (!edk_count) goto PARSE_ERR;

    for (uint16_t i = 0; i < edk_count; ++i) {
        struct aws_cryptosdk_edk edk;

        if (parse_edk(hdr->alloc, &edk, &cur)) {
            goto RETHROW;
        }

        aws_array_list_push_back(&hdr->edk_list, &edk);
    }

    uint8_t content_type;
    if (!aws_byte_cursor_read_u8(&cur, &content_type)) goto SHORT_BUF;

    if (aws_cryptosdk_unlikely(!is_known_type(content_type))) goto PARSE_ERR;
    
    uint32_t reserved; // must be zero
    if (!aws_byte_cursor_read_be32(&cur, &reserved)) goto SHORT_BUF;
    if (reserved) goto PARSE_ERR;

    uint8_t iv_len;
    if (!aws_byte_cursor_read_u8(&cur, &iv_len)) goto SHORT_BUF;

    if (iv_len != aws_cryptosdk_algorithm_ivlen(alg_id)) goto PARSE_ERR;

    uint32_t frame_len;
    if (!aws_byte_cursor_read_be32(&cur, &frame_len)) goto SHORT_BUF;

    if ((content_type == AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED && frame_len != 0) ||
        (content_type == AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED && frame_len == 0)) goto PARSE_ERR;
    hdr->frame_len = frame_len;

    // cur.ptr now points to end of portion of header that is authenticated
    hdr->auth_len = cur.ptr - pcursor->ptr;

    if (aws_byte_buf_init(hdr->alloc, &hdr->iv, iv_len)) goto MEM_ERR;
    if (!aws_byte_cursor_read_and_fill_buffer(&cur, &hdr->iv)) goto SHORT_BUF;

    size_t tag_len = aws_cryptosdk_algorithm_taglen(alg_id);
    if (aws_byte_buf_init(hdr->alloc, &hdr->auth_tag, tag_len)) goto MEM_ERR;
    if (!aws_byte_cursor_read_and_fill_buffer(&cur, &hdr->auth_tag)) goto SHORT_BUF;

    *pcursor = cur;

    return AWS_OP_SUCCESS;

SHORT_BUF:
    aws_cryptosdk_hdr_clear(hdr);
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
PARSE_ERR:
    aws_cryptosdk_hdr_clear(hdr);
    return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
MEM_ERR:
RETHROW:
    aws_cryptosdk_hdr_clear(hdr);
    return AWS_OP_ERR; // Error code will already have been raised in aws_mem_acquire
}

/*
 * Declaring a struct which is initialized to zero does not technically guarantee that the
 * padding bytes will all be zero, according to the C spec, though in practice they generally
 * are. Since we are comparing all of the bytes of the struct, using this union guarantees
 * that even the padding bytes will be zeroes in zero.hdr. It also allows us to fetch an
 * arbitrary array of zero.bytes up to the length of the struct.
 */
static const union {
    uint8_t bytes[sizeof(struct aws_cryptosdk_hdr)];
    struct aws_cryptosdk_hdr hdr;
} zero = {{0}};

static size_t saturating_add(size_t a, size_t b) {
    size_t c = a + b;
    if (c < a) {
        c = SIZE_MAX;
    }
    return c;
}

int aws_cryptosdk_hdr_size(const struct aws_cryptosdk_hdr *hdr) {
    if (!memcmp(hdr, &zero.hdr, sizeof(struct aws_cryptosdk_hdr))) return 0;

    size_t idx;
    size_t edk_count = aws_array_list_length(&hdr->edk_list);
    // 18 is the total size of the non-variable-size fields in the header
    size_t bytes = 18 + MESSAGE_ID_LEN + hdr->iv.len + hdr->auth_tag.len;
    size_t aad_len;

    if (aws_cryptosdk_context_size(&aad_len, &hdr->enc_context)) {
        return -1;
    }
    bytes += aad_len;

    for (idx = 0 ; idx < edk_count ; ++idx) {
        void *vp_edk;
        struct aws_cryptosdk_edk *edk;

        aws_array_list_get_at_ptr(&hdr->edk_list, &vp_edk, idx);

        edk = vp_edk;
        // 2 bytes for each field's length header * 3 fields
        bytes = saturating_add(bytes, 6);
        bytes = saturating_add(bytes, edk->provider_id.len);
        bytes = saturating_add(bytes, edk->provider_info.len);
        bytes = saturating_add(bytes, edk->enc_data_key.len);
    }

    return bytes == SIZE_MAX ? 0 : bytes;
}

int aws_cryptosdk_hdr_write(const struct aws_cryptosdk_hdr *hdr, size_t * bytes_written, uint8_t *outbuf, size_t outlen) {
    struct aws_byte_cursor output = aws_byte_cursor_from_array(outbuf, outlen);

    if (!aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_VERSION_1_0)) goto WRITE_ERR;
    if (!aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED)) goto WRITE_ERR;
    if (!aws_byte_cursor_write_be16(&output, hdr->alg_id)) goto WRITE_ERR;
    if (!aws_byte_cursor_write(&output, hdr->message_id, MESSAGE_ID_LEN)) goto WRITE_ERR;

    // TODO - unify everything on byte_bufs when the aws-c-common refactor lands
    // See: https://github.com/awslabs/aws-c-common/pull/130
    struct aws_byte_cursor aad_length_field = aws_byte_cursor_advance(&output, 2);
    struct aws_byte_buf aad_space = aws_byte_buf_from_array(output.ptr, output.len);

    if (aws_cryptosdk_context_serialize(aws_default_allocator(), &aad_space, &hdr->enc_context)) goto WRITE_ERR;
    output.ptr += aad_space.len;
    output.len -= aad_space.len;

    aws_byte_cursor_write_be16(&aad_length_field, (uint16_t)aad_space.len);

    size_t edk_count = aws_array_list_length(&hdr->edk_list);
    if (!aws_byte_cursor_write_be16(&output, (uint16_t)edk_count)) goto WRITE_ERR;

    for (size_t idx = 0 ; idx < edk_count ; ++idx) {
        void *vp_edk;

        aws_array_list_get_at_ptr(&hdr->edk_list, &vp_edk, idx);

        const struct aws_cryptosdk_edk *edk = vp_edk;

        if (!aws_byte_cursor_write_be16(&output, (uint16_t)edk->provider_id.len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_buffer(&output, &edk->provider_id)) goto WRITE_ERR;

        if (!aws_byte_cursor_write_be16(&output, (uint16_t)edk->provider_info.len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_buffer(&output, &edk->provider_info)) goto WRITE_ERR;

        if (!aws_byte_cursor_write_be16(&output, (uint16_t)edk->enc_data_key.len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_buffer(&output, &edk->enc_data_key)) goto WRITE_ERR;
    }

    if (!aws_byte_cursor_write_u8(
            &output, hdr->frame_len ? AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED : AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED))
        goto WRITE_ERR;

    if (!aws_byte_cursor_write(&output, zero.bytes, 4)) goto WRITE_ERR;

    if (!aws_byte_cursor_write_u8(&output, (uint8_t)hdr->iv.len)) goto WRITE_ERR;
    if (!aws_byte_cursor_write_be32(&output, hdr->frame_len)) goto WRITE_ERR;

    if (!aws_byte_cursor_write_from_whole_buffer(&output, &hdr->iv)) goto WRITE_ERR;
    if (!aws_byte_cursor_write_from_whole_buffer(&output, &hdr->auth_tag)) goto WRITE_ERR;

    *bytes_written = output.ptr - outbuf;
    return AWS_OP_SUCCESS;

WRITE_ERR:
    aws_secure_zero(outbuf, outlen);
    *bytes_written = 0;
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
}
