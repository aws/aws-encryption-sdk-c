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
#include <aws/cryptosdk/header.h>
#include <aws/cryptosdk/private/compiler.h>

#define MESSAGE_ID_LEN 16

struct aws_cryptosdk_hdr {
    uint16_t alg_id;

    uint16_t aad_count;
    uint16_t edk_count;
    size_t frame_len;

    struct aws_byte_buf iv, auth_tag, message_id;
    uint8_t message_id_arr[MESSAGE_ID_LEN];

    struct aws_cryptosdk_hdr_aad *aad_tbl;
    struct aws_cryptosdk_hdr_edk *edk_tbl;
};

int aws_cryptosdk_hdr_alloc(struct aws_cryptosdk_hdr ** hdr) {
    *hdr = malloc(sizeof(struct aws_cryptosdk_hdr));
    if (hdr) return AWS_OP_SUCCESS;
    return AWS_ERROR_OOM;
}

int aws_cryptosdk_hdr_free(struct aws_cryptosdk_hdr * hdr) {
    free(hdr);
    return AWS_OP_SUCCESS;
}

uint16_t aws_cryptosdk_hdr_get_algorithm(const struct aws_cryptosdk_hdr *hdr) {
    return hdr->alg_id;
}

int aws_cryptosdk_hdr_set_algorithm(struct aws_cryptosdk_hdr *hdr, uint16_t alg_id) {
    hdr->alg_id = alg_id;
    return AWS_OP_SUCCESS;
}

size_t aws_cryptosdk_hdr_get_aad_count(const struct aws_cryptosdk_hdr *hdr) {
    return hdr->aad_count;
}

size_t aws_cryptosdk_hdr_get_edk_count(const struct aws_cryptosdk_hdr *hdr) {
    return hdr->edk_count;
}

size_t aws_cryptosdk_hdr_get_frame_len(const struct aws_cryptosdk_hdr *hdr) {
    return hdr->frame_len;
}

int aws_cryptosdk_hdr_set_frame_len(struct aws_cryptosdk_hdr *hdr, size_t frame_len) {
    hdr->frame_len = frame_len;
    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_get_aad(const struct aws_cryptosdk_hdr *hdr, int index, struct aws_cryptosdk_hdr_aad *aad) {
    if (index < 0 || index >= hdr->aad_count) {
        return aws_raise_error(AWS_ERROR_INVALID_INDEX);
    }

    *aad = hdr->aad_tbl[index];

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_set_aad_tbl(struct aws_cryptosdk_hdr *hdr, int count, struct aws_cryptosdk_hdr_aad *aad_tbl) {
    hdr->aad_count = count;
    hdr->aad_tbl = aad_tbl;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_get_edk(const struct aws_cryptosdk_hdr *hdr, int index, struct aws_cryptosdk_hdr_edk *edk) {
    if (index < 0 || index >= hdr->edk_count) {
        return aws_raise_error(AWS_ERROR_INVALID_INDEX);
    }

    *edk = hdr->edk_tbl[index];

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_set_edk_tbl(struct aws_cryptosdk_hdr *hdr, int count, struct aws_cryptosdk_hdr_edk *edk_tbl) {
    hdr->edk_count = count;
    hdr->edk_tbl = edk_tbl;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_get_msgid(const struct aws_cryptosdk_hdr *hdr, struct aws_byte_buf *buf) {
    *buf = hdr->message_id;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_set_msgid(struct aws_cryptosdk_hdr *hdr, uint8_t msg_id[]) {
    memcpy(hdr->message_id_arr, msg_id, MESSAGE_ID_LEN);
    hdr->message_id.len = MESSAGE_ID_LEN;
    hdr->message_id.buffer = hdr->message_id_arr;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_get_iv(const struct aws_cryptosdk_hdr *hdr, struct aws_byte_buf *buf) {
    *buf = hdr->iv;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_set_iv(struct aws_cryptosdk_hdr *hdr, struct aws_byte_buf *buf) {
    hdr->iv = *buf;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_get_authtag(const struct aws_cryptosdk_hdr *hdr, struct aws_byte_buf *buf) {
    *buf = hdr->auth_tag;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_set_authtag(struct aws_cryptosdk_hdr *hdr, struct aws_byte_buf *buf) {
    hdr->auth_tag = *buf;

    return AWS_OP_SUCCESS;
}

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

static int place_ptr_tables(
    struct aws_cryptosdk_hdr * restrict hdr,
    struct aws_byte_cursor * restrict outbuf,
    size_t * restrict header_space_needed
) {
    size_t aad_tbl_size = sizeof(struct aws_cryptosdk_hdr_aad) * hdr->aad_count;
    size_t edk_tbl_size = sizeof(struct aws_cryptosdk_hdr_edk) * hdr->edk_count;

    *header_space_needed += aad_tbl_size + edk_tbl_size;

    hdr->aad_tbl = NULL;
    hdr->edk_tbl = NULL;

    if (!outbuf) {
        return AWS_OP_SUCCESS;
    }

    // Align buffer to a multiple of sizeof(void *) if needed.
    // This isn't strictly guaranteed to work by a strict reading of the C spec, but should work
    // on any real platform.
    uintptr_t align_pad = -(uintptr_t)outbuf->ptr % sizeof(void *);
    uint8_t *ignored;
    if (aws_byte_cursor_skip(outbuf, align_pad)) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    struct aws_byte_cursor slice;
    slice = aws_byte_cursor_advance(outbuf, aad_tbl_size);
    if (!slice.ptr) {
        return aws_raise_error(AWS_ERROR_OOM);
    }
    hdr->aad_tbl = (struct aws_cryptosdk_hdr_aad *)slice.ptr;

    slice = aws_byte_cursor_advance(outbuf, edk_tbl_size);
    if (!slice.ptr) {
        return aws_raise_error(AWS_ERROR_OOM);
    }
    hdr->edk_tbl = (struct aws_cryptosdk_hdr_edk *)slice.ptr;

    return AWS_OP_SUCCESS;
}


/*
 * This helper helps read length-prefixed binary strings from the serialized header.
 * 'inbuf' takes the buffer containing the binary string (and potentially a suffix), and on return
 * contains that suffix only (if any).
 * 'arena' contains a buffer of space into which the field's data will be copied; arena's pointer
 * and length are adjusted to be after the field.
 * 'field' receives a reference to the binary string within the original arena.
 * Finally header_space_needed is incremented by the amount of space consumed from arena.
 *
 * Because we want to use the same codepath for the preparse (determining how much space we need)
 * and parse steps, if arena is null, we will not actually copy the field, but will instead just
 * adjust header_space_needed.
 */
static int read_field_be16(
    struct aws_byte_buf    * restrict field,
    struct aws_byte_cursor * restrict inbuf,
    struct aws_byte_cursor * restrict arena,
    size_t * restrict header_space_needed
) {
    uint16_t length;
    if (aws_byte_cursor_read_be16(inbuf, &length)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    struct aws_byte_cursor field_data = aws_byte_cursor_advance_nospec(inbuf, length);
    if (!field_data.ptr) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    *header_space_needed += length;
    field->len = length;
    field->buffer = NULL;
    if (arena) {
        struct aws_byte_cursor destbuf = aws_byte_cursor_advance_nospec(arena, length);
        if (!destbuf.ptr) return aws_raise_error(AWS_ERROR_OOM);

        memcpy(destbuf.ptr, field_data.ptr, length);
        field->buffer = destbuf.ptr;
    }

    return AWS_OP_SUCCESS;
}

#define PROPAGATE_ERR(expr) do { \
    int prop_err_rv = (expr); \
    if (aws_cryptosdk_unlikely(prop_err_rv)) return prop_err_rv; \
} while (0)

static inline int hdr_parse_core(
    struct aws_cryptosdk_hdr * restrict hdr,
    struct aws_byte_cursor * restrict outbuf,
    struct aws_byte_cursor * restrict inbuf,
    size_t * restrict header_space_needed
) {
    assert(hdr);
    assert(inbuf);
    assert(header_space_needed);

    uint8_t bytefield;
    if (aws_byte_cursor_read_u8(inbuf, &bytefield)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    if (aws_cryptosdk_unlikely(bytefield != AWS_CRYPTOSDK_HEADER_VERSION_1_0)) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);

    if (aws_byte_cursor_read_u8(inbuf, &bytefield)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    if (aws_cryptosdk_unlikely(bytefield != AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED)) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);

    uint16_t alg_id;
    if (aws_byte_cursor_read_be16(inbuf, &alg_id)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    if (aws_cryptosdk_unlikely(!aws_cryptosdk_algorithm_is_known(alg_id))) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }
    hdr->alg_id = alg_id;

    if (aws_byte_cursor_read(inbuf, hdr->message_id_arr, MESSAGE_ID_LEN)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    hdr->message_id.len = MESSAGE_ID_LEN;
    hdr->message_id.buffer = hdr->message_id_arr;

    uint16_t aad_len;
    if (aws_byte_cursor_read_be16(inbuf, &aad_len)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    const uint8_t *expect_end_aad = (const uint8_t *)inbuf->ptr + aad_len;

    if (aws_byte_cursor_read_be16(inbuf, &hdr->aad_count)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    struct aws_byte_cursor aad_start = *inbuf;

    // Skip forward and get the EDK count, so we can preallocate our tables
    if (aws_cryptosdk_unlikely(aws_byte_cursor_skip(inbuf, aad_len - 2))) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (aws_byte_cursor_read_be16(inbuf, &hdr->edk_count)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    if (aws_cryptosdk_unlikely(!hdr->edk_count)) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);

    if (place_ptr_tables(hdr, outbuf, header_space_needed)) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    // Now go back and parse the AAD entries
    *inbuf = aad_start;

    for (size_t i = 0; i < hdr->aad_count; i++) {
        struct aws_cryptosdk_hdr_aad aad;

        PROPAGATE_ERR(read_field_be16(&aad.key, inbuf, outbuf, header_space_needed));
        PROPAGATE_ERR(read_field_be16(&aad.value, inbuf, outbuf, header_space_needed));

        if (hdr->aad_tbl) {
            hdr->aad_tbl[i] = aad;
        }
    }

    if (inbuf->ptr != expect_end_aad) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    // Skip the EDK count as we've already read it
    if (aws_byte_cursor_skip(inbuf, 2)) return aws_raise_error(AWS_ERROR_UNKNOWN);

    // The EDK structure doesn't have a handy length field, so we need to walk it here.
    for (int i = 0; i < hdr->edk_count; i++) {
        struct aws_cryptosdk_hdr_edk edk;
        
        PROPAGATE_ERR(read_field_be16(&edk.provider_id, inbuf, outbuf, header_space_needed));
        PROPAGATE_ERR(read_field_be16(&edk.provider_info, inbuf, outbuf, header_space_needed));
        PROPAGATE_ERR(read_field_be16(&edk.enc_data_key, inbuf, outbuf, header_space_needed));

        if (hdr->edk_tbl) {
            hdr->edk_tbl[i] = edk;
        }
    }

    uint8_t content_type;
    if (aws_byte_cursor_read_u8(inbuf, &content_type)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    if (aws_cryptosdk_unlikely(!is_known_type(content_type))) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    // skip reserved
    if (aws_byte_cursor_skip(inbuf, 4)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    uint8_t ivlen;
    if (aws_byte_cursor_read_u8(inbuf, &ivlen)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    if (ivlen != aws_cryptosdk_algorithm_ivlen(alg_id)) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    uint32_t frame_len;
    if (aws_byte_cursor_read_be32(inbuf, &frame_len)) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    if (content_type == AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED && frame_len != 0) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    if (content_type == AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED && frame_len == 0) {
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
    }

    hdr->frame_len = frame_len;

    struct aws_byte_cursor iv_src = aws_byte_cursor_advance_nospec(inbuf, ivlen);
    if (!iv_src.ptr) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    struct aws_byte_cursor iv_dst = { .ptr = NULL, .len = 0 };
    if (outbuf) {
        iv_dst = aws_byte_cursor_advance(outbuf, ivlen);
        if (!iv_dst.ptr) return aws_raise_error(AWS_ERROR_OOM);
        memcpy(iv_dst.ptr, iv_src.ptr, ivlen);
    }

    hdr->iv.buffer = iv_dst.ptr;
    hdr->iv.len = ivlen;

    *header_space_needed += ivlen;

    // verify we can still fit header auth
    size_t taglen = aws_cryptosdk_algorithm_taglen(alg_id);
    struct aws_byte_cursor hdr_auth_src = aws_byte_cursor_advance_nospec(inbuf, taglen);
    if (!hdr_auth_src.ptr) return aws_raise_error(AWS_ERROR_SHORT_BUFFER);

    struct aws_byte_cursor hdr_auth_dst = { .ptr = NULL, .len = 0 };
    if (outbuf) {
        hdr_auth_dst = aws_byte_cursor_advance(outbuf, taglen);
        if (!hdr_auth_dst.ptr) return aws_raise_error(AWS_ERROR_OOM);
        memcpy(hdr_auth_dst.ptr, hdr_auth_src.ptr, taglen);
    }

    hdr->auth_tag.buffer = hdr_auth_dst.ptr;
    hdr->auth_tag.len = taglen;

    *header_space_needed += taglen;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_hdr_preparse(const uint8_t *hdrbuf, size_t buflen, size_t *header_space_needed, size_t *header_length) {
    struct aws_byte_cursor inbuf;
    inbuf.ptr = (void *)hdrbuf;
    inbuf.len = buflen;

    struct aws_cryptosdk_hdr hdr;

    *header_space_needed = sizeof(hdr);
    // Reserve space for alignment padding
    *header_space_needed += sizeof(void *) - 1;

    int rv = hdr_parse_core(&hdr, NULL, &inbuf, header_space_needed);

    if (aws_cryptosdk_likely(rv == AWS_OP_SUCCESS)) {
        *header_length = (const uint8_t *)inbuf.ptr - hdrbuf;
        *header_space_needed += *header_length;
    }

    return rv;
}

int aws_cryptosdk_hdr_parse(
    struct aws_cryptosdk_hdr **hdr,
    uint8_t *outbufp, size_t outlen,
    const uint8_t *inbufp, size_t inlen
) {
    struct aws_byte_cursor inbuf = { .ptr = (void *)inbufp, .len = inlen };
    struct aws_byte_cursor outbuf = { .ptr = (void *)outbufp, .len = outlen };

    // Align header to the size of a void *
    uintptr_t align = -(uintptr_t)outbufp % sizeof(void *);

    // Don't need to check result: If we don't have enough space for a void *, then we definitely
    // won't have enough for the full header structure (and thus the next advance will fail instead).
    aws_byte_cursor_skip(&outbuf, align);

    struct aws_cryptosdk_hdr *pHeader;
    struct aws_byte_cursor tmp = aws_byte_cursor_advance(&outbuf, sizeof(*pHeader));
    if (!tmp.ptr) return aws_raise_error(AWS_ERROR_OOM);
    pHeader = (struct aws_cryptosdk_hdr *)tmp.ptr;

    if (aws_cryptosdk_unlikely(!pHeader)) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    size_t header_space_needed = 0;
    int rv = hdr_parse_core(pHeader, &outbuf, &inbuf, &header_space_needed);

    if (aws_cryptosdk_unlikely(rv != AWS_OP_SUCCESS)) {
        *hdr = NULL;
        return rv;
    }
   
    *hdr = pHeader;
    return rv;
}

int aws_cryptosdk_hdr_write(const struct aws_cryptosdk_hdr *hdr, size_t * bytes_written, uint8_t *outbuf, size_t outlen) {
    *bytes_written = 0;
    struct aws_byte_cursor output = aws_byte_cursor_from_array(outbuf, outlen);

    if (aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_VERSION_1_0)) return aws_raise_error(AWS_ERROR_OOM);
    ++ *bytes_written;

    if (aws_byte_cursor_write_u8(&output, AWS_CRYPTOSDK_HEADER_TYPE_CUSTOMER_AED)) return aws_raise_error(AWS_ERROR_OOM);
    ++ *bytes_written;

    if (aws_byte_cursor_write_be16(&output, hdr->alg_id)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += 2;

    if (aws_byte_cursor_copy_byte_buffer(&output, &hdr->message_id)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += hdr->message_id.len;

    // read through AAD once to calculate length
    int idx;
    uint16_t aad_len = 2; // key-value pair count
    for (idx = 0 ; idx < hdr->aad_count ; ++idx) {
        struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;
        aad_len += 4 + aad->key.len + aad->value.len; // key len (2 bytes), val len (2 bytes), key, value
    }

    if (aws_byte_cursor_write_be16(&output, aad_len)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += 2;

    if (aws_byte_cursor_write_be16(&output, hdr->aad_count)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += 2;

    for (idx = 0 ; idx < hdr->aad_count ; ++idx) {
        struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + idx;

        if (aws_byte_cursor_write_be16(&output, aad->key.len)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += 2;

        if (aws_byte_cursor_copy_byte_buffer(&output, &aad->key)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += aad->key.len;

        if (aws_byte_cursor_write_be16(&output, aad->value.len)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += 2;

        if (aws_byte_cursor_copy_byte_buffer(&output, &aad->value)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += aad->value.len;
    }

    if (aws_byte_cursor_write_be16(&output, hdr->edk_count)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += 2;

    for (idx = 0 ; idx < hdr->edk_count ; ++idx) {
        struct aws_cryptosdk_hdr_edk * edk = hdr->edk_tbl + idx;

        if (aws_byte_cursor_write_be16(&output, edk->provider_id.len)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += 2;

        if (aws_byte_cursor_copy_byte_buffer(&output, &edk->provider_id)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += edk->provider_id.len;

        if (aws_byte_cursor_write_be16(&output, edk->provider_info.len)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += 2;

        if (aws_byte_cursor_copy_byte_buffer(&output, &edk->provider_info)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += edk->provider_info.len;

        if (aws_byte_cursor_write_be16(&output, edk->enc_data_key.len)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += 2;

        if (aws_byte_cursor_copy_byte_buffer(&output, &edk->enc_data_key)) return aws_raise_error(AWS_ERROR_OOM);
        *bytes_written += edk->enc_data_key.len;
    }

    if (aws_byte_cursor_write_u8(
            &output, hdr->frame_len ? AWS_CRYPTOSDK_HEADER_CTYPE_FRAMED : AWS_CRYPTOSDK_HEADER_CTYPE_NONFRAMED))
        return aws_raise_error(AWS_ERROR_OOM);
    ++ *bytes_written;

    if (aws_byte_cursor_write_u32(&output, 0)) return aws_raise_error(AWS_ERROR_OOM); // reserved bytes
    *bytes_written += 4;

    if (aws_byte_cursor_write_u8(&output, hdr->iv.len)) return aws_raise_error(AWS_ERROR_OOM);
    ++ *bytes_written;

    if (aws_byte_cursor_write_be32(&output, hdr->frame_len)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += 4;

    if (aws_byte_cursor_copy_byte_buffer(&output, &hdr->iv)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += hdr->iv.len;

    if (aws_byte_cursor_copy_byte_buffer(&output, &hdr->auth_tag)) return aws_raise_error(AWS_ERROR_OOM);
    *bytes_written += hdr->auth_tag.len;

    return AWS_OP_SUCCESS;
}
