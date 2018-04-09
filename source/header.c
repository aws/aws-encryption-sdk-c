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

int aws_cryptosdk_algorithm_is_known(uint16_t alg_id) {
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

static inline void hdr_zeroize(struct aws_cryptosdk_hdr *hdr) {
    memset(hdr, 0, sizeof(struct aws_cryptosdk_hdr));
}

void aws_cryptosdk_hdr_free(struct aws_allocator * allocator, struct aws_cryptosdk_hdr *hdr) {
    if (hdr->aad_tbl) {
        for (size_t i = 0; i < hdr->aad_count ; ++i) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + i;
            aws_byte_buf_free(allocator, &aad->key);
            aws_byte_buf_free(allocator, &aad->value);
        }
        allocator->mem_release(allocator, hdr->aad_tbl);
    }
    if (hdr->edk_tbl) {
        for (size_t i = 0; i < hdr->edk_count; ++i) {
            struct aws_cryptosdk_hdr_edk * edk = hdr->edk_tbl + i;
            aws_byte_buf_free(allocator, &edk->provider_id);
            aws_byte_buf_free(allocator, &edk->provider_info);
            aws_byte_buf_free(allocator, &edk->enc_data_key);
        }
        allocator->mem_release(allocator, hdr->edk_tbl);
    }
    aws_byte_buf_free(allocator, &hdr->iv);
    aws_byte_buf_free(allocator, &hdr->auth_tag);
    hdr_zeroize(hdr);
}

int aws_cryptosdk_hdr_parse(struct aws_allocator * allocator, struct aws_cryptosdk_hdr *hdr, const uint8_t *src, size_t src_len) {
    int ret;
    struct aws_byte_cursor cur = aws_byte_cursor_from_array(src, src_len);

    hdr_zeroize(hdr);

    uint8_t bytefield;
    if (aws_byte_cursor_read_u8(&cur, &bytefield)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    if (aws_cryptosdk_unlikely(bytefield != AWS_CRYPTOSDK_HEADER_VERSION_1_0)) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);

    if (aws_byte_cursor_read_u8(&cur, &bytefield)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    if (aws_cryptosdk_unlikely(bytefield != AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED)) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);

    uint16_t alg_id;
    if (aws_byte_cursor_read_be16(&cur, &alg_id)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    if (aws_cryptosdk_unlikely(!aws_cryptosdk_algorithm_is_known(alg_id))) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }
    hdr->alg_id = alg_id;

    if (aws_byte_cursor_read(&cur, hdr->message_id, MESSAGE_ID_LEN)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    uint16_t aad_len;
    if (aws_byte_cursor_read_be16(&cur, &aad_len)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    if (aad_len) {
        int aad_len_remaining = aad_len;

        uint16_t aad_count;
        if (aws_byte_cursor_read_be16(&cur, &aad_count)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        aad_len_remaining -= 2;
        hdr->aad_count = aad_count;

        size_t aad_tbl_size = aad_count*sizeof(struct aws_cryptosdk_hdr_aad);
        hdr->aad_tbl = allocator->mem_acquire(allocator, aad_tbl_size);
        if (!hdr->aad_tbl) {ret = AWS_ERROR_OOM; goto PARSE_ERR;}
        memset(hdr->aad_tbl, 0, aad_tbl_size); // so we don't try to free uninitialized memory

        for (size_t i = 0; i < hdr->aad_count; ++i) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + i;
            uint16_t key_len;
            ret = aws_byte_cursor_read_be16(&cur, &key_len); if (ret) goto PARSE_ERR;
            aad_len_remaining -= 2;

            if (key_len > aad_len_remaining) { ret = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT; goto PARSE_ERR; }

            ret = aws_byte_buf_alloc(allocator, &aad->key, key_len); if (ret) goto PARSE_ERR;

            ret = aws_byte_cursor_read_and_fill_buffer(&cur, &aad->key); if (ret) goto PARSE_ERR;
            aad_len_remaining -= key_len;

            uint16_t value_len;
            ret = aws_byte_cursor_read_be16(&cur, &value_len); if (ret) goto PARSE_ERR;
            aad_len_remaining -= 2;

            if (value_len > aad_len_remaining) { ret = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT; goto PARSE_ERR; }

            ret = aws_byte_buf_alloc(allocator, &aad->value, value_len); if (ret) goto PARSE_ERR;

            ret = aws_byte_cursor_read_and_fill_buffer(&cur, &aad->value); if (ret) goto PARSE_ERR;
            aad_len_remaining -= value_len;
        }

        if (aad_len_remaining) { ret = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT; goto PARSE_ERR; }
    }

    uint16_t edk_count;
    ret = aws_byte_cursor_read_be16(&cur, &edk_count); if (ret) goto PARSE_ERR;
    hdr->edk_count = edk_count;

    size_t edk_tbl_size = edk_count*sizeof(struct aws_cryptosdk_hdr_edk);
    hdr->edk_tbl = allocator->mem_acquire(allocator, edk_tbl_size);
    if (!hdr->edk_tbl) {ret = AWS_ERROR_OOM; goto PARSE_ERR;}
    memset(hdr->edk_tbl, 0, edk_tbl_size);

    for (size_t i = 0; i < hdr->edk_count; ++i) {
        struct aws_cryptosdk_hdr_edk * edk = hdr->edk_tbl + i;
        uint16_t field_len;

        ret = aws_byte_cursor_read_be16(&cur, &field_len); if (ret) goto PARSE_ERR;
        ret = aws_byte_buf_alloc(allocator, &edk->provider_id, field_len); if (ret) goto PARSE_ERR;
        ret = aws_byte_cursor_read_and_fill_buffer(&cur, &edk->provider_id); if (ret) goto PARSE_ERR;

        ret = aws_byte_cursor_read_be16(&cur, &field_len); if (ret) goto PARSE_ERR;
        ret = aws_byte_buf_alloc(allocator, &edk->provider_info, field_len); if (ret) goto PARSE_ERR;
        ret = aws_byte_cursor_read_and_fill_buffer(&cur, &edk->provider_info); if (ret) goto PARSE_ERR;

        ret = aws_byte_cursor_read_be16(&cur, &field_len); if (ret) goto PARSE_ERR;
        ret = aws_byte_buf_alloc(allocator, &edk->enc_data_key, field_len); if (ret) goto PARSE_ERR;
        ret = aws_byte_cursor_read_and_fill_buffer(&cur, &edk->enc_data_key); if (ret) goto PARSE_ERR;
    }

    uint8_t content_type;
    ret = aws_byte_cursor_read_u8(&cur, &content_type); if (ret) goto PARSE_ERR;

    if (aws_cryptosdk_unlikely(!is_known_type(content_type))) {
        ret = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT; goto PARSE_ERR;
    }
    
    // skip reserved
    ret = aws_byte_cursor_skip(&cur, 4); if (ret) goto PARSE_ERR;

    uint8_t iv_len;
    ret = aws_byte_cursor_read_u8(&cur, &iv_len); if (ret) goto PARSE_ERR;

    if (iv_len != aws_cryptosdk_algorithm_ivlen(alg_id)) {
        ret = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT; goto PARSE_ERR;
    }

    uint32_t frame_len;
    ret = aws_byte_cursor_read_be32(&cur, &frame_len); if (ret) goto PARSE_ERR;

    if ((content_type == AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED && frame_len != 0) ||
        (content_type == AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED && frame_len == 0)) {
        ret = AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT; goto PARSE_ERR;
    }
    hdr->frame_len = frame_len;

    // cur.ptr now points to end of portion of header that is authenticated
    hdr->auth_len = cur.ptr - src;

    ret = aws_byte_buf_alloc(allocator, &hdr->iv, iv_len); if (ret) goto PARSE_ERR;
    ret = aws_byte_cursor_read_and_fill_buffer(&cur, &hdr->iv); if (ret) goto PARSE_ERR;

    size_t tag_len = aws_cryptosdk_algorithm_taglen(alg_id);
    ret = aws_byte_buf_alloc(allocator, &hdr->auth_tag, tag_len); if (ret) goto PARSE_ERR;
    ret = aws_byte_cursor_read_and_fill_buffer(&cur, &hdr->auth_tag); if (ret) goto PARSE_ERR;

    return AWS_OP_SUCCESS;

PARSE_ERR:
    aws_cryptosdk_hdr_free(allocator, hdr);
    return aws_raise_error(ret);
}

static const union {
    uint8_t bytes[sizeof(struct aws_cryptosdk_hdr)];
    struct aws_cryptosdk_hdr hdr;
} zero = {0};

int aws_cryptosdk_hdr_size(const struct aws_cryptosdk_hdr *hdr) {
    if (!memcmp(hdr, &zero.hdr, sizeof(struct aws_cryptosdk_hdr))) return 0;

    int idx;
    int bytes = 18 + MESSAGE_ID_LEN + hdr->iv.len + hdr->auth_tag.len + (hdr->aad_count ? 2 : 0);

    for (idx = 0 ; idx < hdr->aad_count ; ++idx) {
        struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;
        bytes += 4 + aad->key.len + aad->value.len;
    }

    for (idx = 0 ; idx < hdr->edk_count ; ++idx) {
        struct aws_cryptosdk_hdr_edk * edk = hdr->edk_tbl + idx;
        bytes += 6 + edk->provider_id.len + edk->provider_info.len + edk->enc_data_key.len;
    }
    return bytes;
}

int aws_cryptosdk_hdr_write(const struct aws_cryptosdk_hdr *hdr, size_t * bytes_written, uint8_t *outbuf, size_t outlen) {
    struct aws_byte_cursor output = aws_byte_cursor_from_array(outbuf, outlen);

    if (aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_VERSION_1_0)) goto WRITE_ERR;
    if (aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED)) goto WRITE_ERR;
    if (aws_byte_cursor_write_be16(&output, hdr->alg_id)) goto WRITE_ERR;
    if (aws_byte_cursor_write(&output, hdr->message_id, MESSAGE_ID_LEN)) goto WRITE_ERR;

    if (hdr->aad_count) {

        // read through AAD once to calculate length
        uint16_t aad_len = 2; // key-value pair count
        for (int idx = 0 ; idx < hdr->aad_count ; ++idx) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;
            aad_len += 4 + aad->key.len + aad->value.len; // key len (2 bytes), val len (2 bytes), key, value
        }

        if (aws_byte_cursor_write_be16(&output, aad_len)) goto WRITE_ERR;

        if (aws_byte_cursor_write_be16(&output, hdr->aad_count)) goto WRITE_ERR;

        for (int idx = 0 ; idx < hdr->aad_count ; ++idx) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;

            if (aws_byte_cursor_write_be16(&output, aad->key.len)) goto WRITE_ERR;
            if (aws_byte_cursor_write_from_whole_buffer(&output, &aad->key)) goto WRITE_ERR;

            if (aws_byte_cursor_write_be16(&output, aad->value.len)) goto WRITE_ERR;
            if (aws_byte_cursor_write_from_whole_buffer(&output, &aad->value)) goto WRITE_ERR;

        }

    } else {
        // when no AAD, message format includes 16-bit field of zero for AAD len, but no AAD count field
        if (aws_byte_cursor_write_be16(&output, 0)) goto WRITE_ERR;
    }

    if (aws_byte_cursor_write_be16(&output, hdr->edk_count)) goto WRITE_ERR;

    for (int idx = 0 ; idx < hdr->edk_count ; ++idx) {
        struct aws_cryptosdk_hdr_edk * edk = hdr->edk_tbl + idx;

        if (aws_byte_cursor_write_be16(&output, edk->provider_id.len)) goto WRITE_ERR;
        if (aws_byte_cursor_write_from_whole_buffer(&output, &edk->provider_id)) goto WRITE_ERR;

        if (aws_byte_cursor_write_be16(&output, edk->provider_info.len)) goto WRITE_ERR;
        if (aws_byte_cursor_write_from_whole_buffer(&output, &edk->provider_info)) goto WRITE_ERR;

        if (aws_byte_cursor_write_be16(&output, edk->enc_data_key.len)) goto WRITE_ERR;
        if (aws_byte_cursor_write_from_whole_buffer(&output, &edk->enc_data_key)) goto WRITE_ERR;
    }

    if (aws_byte_cursor_write_u8(
            &output, hdr->frame_len ? AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED : AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED))
        return aws_raise_error(AWS_ERROR_OOM);

    if (aws_byte_cursor_write(&output, zero.bytes, 4)) goto WRITE_ERR;

    if (aws_byte_cursor_write_u8(&output, hdr->iv.len)) goto WRITE_ERR;
    if (aws_byte_cursor_write_be32(&output, hdr->frame_len)) goto WRITE_ERR;

    if (aws_byte_cursor_write_from_whole_buffer(&output, &hdr->iv)) goto WRITE_ERR;
    if (aws_byte_cursor_write_from_whole_buffer(&output, &hdr->auth_tag)) goto WRITE_ERR;

    *bytes_written = output.ptr - outbuf;
    return AWS_OP_SUCCESS;

WRITE_ERR:
    memset(outbuf, 0, outlen);
    *bytes_written = 0;
    return aws_raise_error(AWS_ERROR_OOM);
}
