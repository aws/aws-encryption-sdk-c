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
#include <aws/cryptosdk/cipher.h> // aws_cryptosdk_secure_zero
#include <aws/cryptosdk/error.h>
#include <aws/common/byte_buf.h>

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
    aws_secure_zero(hdr, sizeof(struct aws_cryptosdk_hdr));
}

void aws_cryptosdk_hdr_clean_up(struct aws_allocator * allocator, struct aws_cryptosdk_hdr *hdr) {
    if (hdr->aad_tbl) {
        for (size_t i = 0; i < hdr->aad_count ; ++i) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + i;
            aws_byte_buf_clean_up(&aad->key);
            aws_byte_buf_clean_up(&aad->value);
        }
        aws_mem_release(allocator, hdr->aad_tbl);
    }
    if (hdr->edk_tbl) {
        for (size_t i = 0; i < hdr->edk_count; ++i) {
            struct aws_cryptosdk_edk * edk = hdr->edk_tbl + i;
            aws_byte_buf_clean_up(&edk->provider_id);
            aws_byte_buf_clean_up(&edk->provider_info);
            aws_byte_buf_clean_up(&edk->enc_data_key);
        }
        aws_mem_release(allocator, hdr->edk_tbl);
    }
    aws_byte_buf_clean_up(&hdr->iv);
    aws_byte_buf_clean_up(&hdr->auth_tag);
    hdr_zeroize(hdr);
}

int aws_cryptosdk_hdr_parse_init(struct aws_allocator * allocator, struct aws_cryptosdk_hdr *hdr, const uint8_t *src, size_t src_len) {
    struct aws_byte_cursor cur = aws_byte_cursor_from_array(src, src_len);

    hdr_zeroize(hdr); // needed so that clean up function works properly on errors

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
        uint8_t * aad_end = cur.ptr + aad_len;

        uint16_t aad_count;
        if (!aws_byte_cursor_read_be16(&cur, &aad_count)) goto SHORT_BUF;
        // aad_count may not be zero. In the case of empty encryption context, aad_len must
        // be zero and the AAD field in the header is skipped entirely.
        if (!aad_count) goto PARSE_ERR;
        hdr->aad_count = aad_count;

        size_t aad_tbl_size = aad_count*sizeof(struct aws_cryptosdk_hdr_aad);
        hdr->aad_tbl = aws_mem_acquire(allocator, aad_tbl_size);
        if (!hdr->aad_tbl) goto MEM_ERR;
        aws_secure_zero(hdr->aad_tbl, aad_tbl_size); // so we don't try to free uninitialized memory

        for (size_t i = 0; i < hdr->aad_count; ++i) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + i;
            uint16_t key_len;
            if (!aws_byte_cursor_read_be16(&cur, &key_len)) goto SHORT_BUF;

            if (key_len) {
                // "+ 2" because there is at least a value len field remaining
                if (cur.ptr + key_len + 2 > aad_end) goto PARSE_ERR;

                if (aws_byte_buf_init(allocator, &aad->key, key_len)) goto MEM_ERR;

                if (!aws_byte_cursor_read_and_fill_buffer(&cur, &aad->key)) goto SHORT_BUF;
            }
            uint16_t value_len;
            if (!aws_byte_cursor_read_be16(&cur, &value_len)) goto SHORT_BUF;

            if (value_len) {
                if (cur.ptr + value_len > aad_end) goto PARSE_ERR;

                if (aws_byte_buf_init(allocator, &aad->value, value_len)) goto MEM_ERR;

                if (!aws_byte_cursor_read_and_fill_buffer(&cur, &aad->value)) goto SHORT_BUF;
            }
        }

        if (cur.ptr != aad_end) goto PARSE_ERR;
    }

    uint16_t edk_count;
    if (!aws_byte_cursor_read_be16(&cur, &edk_count)) goto SHORT_BUF;
    if (!edk_count) goto PARSE_ERR;
    hdr->edk_count = edk_count;

    size_t edk_tbl_size = edk_count*sizeof(struct aws_cryptosdk_edk);
    hdr->edk_tbl = aws_mem_acquire(allocator, edk_tbl_size);
    if (!hdr->edk_tbl) goto MEM_ERR;
    aws_secure_zero(hdr->edk_tbl, edk_tbl_size); // so we don't try to free uninitialized memory

    for (size_t i = 0; i < hdr->edk_count; ++i) {
        struct aws_cryptosdk_edk * edk = hdr->edk_tbl + i;
        uint16_t field_len;

        if (!aws_byte_cursor_read_be16(&cur, &field_len)) goto SHORT_BUF;
        if (aws_byte_buf_init(allocator, &edk->provider_id, field_len)) goto MEM_ERR;
        if (!aws_byte_cursor_read_and_fill_buffer(&cur, &edk->provider_id)) goto SHORT_BUF;

        if (!aws_byte_cursor_read_be16(&cur, &field_len)) goto SHORT_BUF;
        if (aws_byte_buf_init(allocator, &edk->provider_info, field_len)) goto MEM_ERR;
        if (!aws_byte_cursor_read_and_fill_buffer(&cur, &edk->provider_info)) goto SHORT_BUF;

        if (!aws_byte_cursor_read_be16(&cur, &field_len)) goto SHORT_BUF;
        if (aws_byte_buf_init(allocator, &edk->enc_data_key, field_len)) goto MEM_ERR;
        if (!aws_byte_cursor_read_and_fill_buffer(&cur, &edk->enc_data_key)) goto SHORT_BUF;
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
    hdr->auth_len = cur.ptr - src;

    if (aws_byte_buf_init(allocator, &hdr->iv, iv_len)) goto MEM_ERR;
    if (!aws_byte_cursor_read_and_fill_buffer(&cur, &hdr->iv)) goto SHORT_BUF;

    size_t tag_len = aws_cryptosdk_algorithm_taglen(alg_id);
    if (aws_byte_buf_init(allocator, &hdr->auth_tag, tag_len)) goto MEM_ERR;
    if (!aws_byte_cursor_read_and_fill_buffer(&cur, &hdr->auth_tag)) goto SHORT_BUF;

    return AWS_OP_SUCCESS;

SHORT_BUF:
    aws_cryptosdk_hdr_clean_up(allocator, hdr);
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
PARSE_ERR:
    aws_cryptosdk_hdr_clean_up(allocator, hdr);
    return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
MEM_ERR:
    aws_cryptosdk_hdr_clean_up(allocator, hdr);
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

int aws_cryptosdk_hdr_size(const struct aws_cryptosdk_hdr *hdr) {
    if (!memcmp(hdr, &zero.hdr, sizeof(struct aws_cryptosdk_hdr))) return 0;

    int idx;
    int bytes = 18 + MESSAGE_ID_LEN + hdr->iv.len + hdr->auth_tag.len + (hdr->aad_count ? 2 : 0);

    for (idx = 0 ; idx < hdr->aad_count ; ++idx) {
        struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;
        bytes += 4 + aad->key.len + aad->value.len;
    }

    for (idx = 0 ; idx < hdr->edk_count ; ++idx) {
        struct aws_cryptosdk_edk * edk = hdr->edk_tbl + idx;
        bytes += 6 + edk->provider_id.len + edk->provider_info.len + edk->enc_data_key.len;
    }
    return bytes;
}

int aws_cryptosdk_hdr_write(const struct aws_cryptosdk_hdr *hdr, size_t * bytes_written, uint8_t *outbuf, size_t outlen) {
    struct aws_byte_cursor output = aws_byte_cursor_from_array(outbuf, outlen);

    if (!aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_VERSION_1_0)) goto WRITE_ERR;
    if (!aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED)) goto WRITE_ERR;
    if (!aws_byte_cursor_write_be16(&output, hdr->alg_id)) goto WRITE_ERR;
    if (!aws_byte_cursor_write(&output, hdr->message_id, MESSAGE_ID_LEN)) goto WRITE_ERR;

    if (hdr->aad_count) {

        // read through AAD once to calculate length
        uint16_t aad_len = 2; // key-value pair count
        for (int idx = 0 ; idx < hdr->aad_count ; ++idx) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;
            aad_len += 4 + aad->key.len + aad->value.len; // key len (2 bytes), val len (2 bytes), key, value
        }

        if (!aws_byte_cursor_write_be16(&output, aad_len)) goto WRITE_ERR;

        if (!aws_byte_cursor_write_be16(&output, hdr->aad_count)) goto WRITE_ERR;

        for (int idx = 0 ; idx < hdr->aad_count ; ++idx) {
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;

            if (!aws_byte_cursor_write_be16(&output, aad->key.len)) goto WRITE_ERR;
            if (!aws_byte_cursor_write_from_whole_buffer(&output, &aad->key)) goto WRITE_ERR;

            if (!aws_byte_cursor_write_be16(&output, aad->value.len)) goto WRITE_ERR;
            if (!aws_byte_cursor_write_from_whole_buffer(&output, &aad->value)) goto WRITE_ERR;

        }

    } else {
        // when no AAD, message format includes 16-bit field of zero for AAD len, but no AAD count field
        if (!aws_byte_cursor_write_be16(&output, 0)) goto WRITE_ERR;
    }

    if (!aws_byte_cursor_write_be16(&output, hdr->edk_count)) goto WRITE_ERR;

    for (int idx = 0 ; idx < hdr->edk_count ; ++idx) {
        struct aws_cryptosdk_edk * edk = hdr->edk_tbl + idx;

        if (!aws_byte_cursor_write_be16(&output, edk->provider_id.len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_buffer(&output, &edk->provider_id)) goto WRITE_ERR;

        if (!aws_byte_cursor_write_be16(&output, edk->provider_info.len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_buffer(&output, &edk->provider_info)) goto WRITE_ERR;

        if (!aws_byte_cursor_write_be16(&output, edk->enc_data_key.len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_buffer(&output, &edk->enc_data_key)) goto WRITE_ERR;
    }

    if (!aws_byte_cursor_write_u8(
            &output, hdr->frame_len ? AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED : AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED))
        goto WRITE_ERR;

    if (!aws_byte_cursor_write(&output, zero.bytes, 4)) goto WRITE_ERR;

    if (!aws_byte_cursor_write_u8(&output, hdr->iv.len)) goto WRITE_ERR;
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
