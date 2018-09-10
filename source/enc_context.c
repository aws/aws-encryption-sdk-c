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
#include <aws/cryptosdk/private/enc_context.h>
#include <aws/cryptosdk/private/utils.h>
#include <aws/cryptosdk/error.h>

#include <aws/common/byte_buf.h>

int aws_cryptosdk_context_size(size_t *size, const struct aws_hash_table *enc_context) {
    size_t serialized_len = 2; // First two bytes are the number of k-v pairs
    size_t entry_count = 0;

    for (struct aws_hash_iter iter = aws_hash_iter_begin(enc_context);
         !aws_hash_iter_done(&iter); aws_hash_iter_next(&iter))
    {
        entry_count++;

        if (entry_count > UINT16_MAX) {
            return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
        }

        const struct aws_string *key = iter.element.key;
        const struct aws_string *value = iter.element.value;
        serialized_len += 2 /* key length */ + key->len +
            2 /* value length */ + value->len;

        if (serialized_len > UINT16_MAX) {
            return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
        }
    }

    if (entry_count == 0) {
        // Empty context.
        *size = 0;
        return AWS_OP_SUCCESS;
    }

    *size = serialized_len;

    return AWS_OP_SUCCESS;
}

int aws_cryptosdk_context_serialize(struct aws_allocator *alloc,
                                    struct aws_byte_buf *output,
                                    const struct aws_hash_table *enc_context) {
    size_t length;
    if (aws_cryptosdk_context_size(&length, enc_context)) {
        return AWS_OP_ERR;
    }

    if (output->capacity < length) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (length == 0) {
        // Empty encryption context
        output->len = 0;
        return AWS_OP_SUCCESS;
    }

    size_t num_elems = aws_hash_table_get_entry_count(enc_context);

    struct aws_array_list elems;
    if (aws_cryptosdk_hash_elems_array_init(alloc, &elems, enc_context)) return AWS_OP_ERR;

    aws_array_list_sort(&elems, aws_cryptosdk_compare_hash_elems_by_key_string);

    output->len = length;
    struct aws_byte_cursor cur = aws_byte_cursor_from_buf(output);

    if (!aws_byte_cursor_write_be16(&cur, num_elems)) goto WRITE_ERR;

    for (size_t idx = 0; idx < num_elems; ++idx) {
        struct aws_hash_element elem;
        if (aws_array_list_get_at(&elems, (void *)&elem, idx)) {
            aws_array_list_clean_up(&elems);
            return AWS_OP_ERR;
        }
        const struct aws_string * key = (const struct aws_string *)elem.key;
        const struct aws_string * value = (const struct aws_string *)elem.value;
        if (!aws_byte_cursor_write_be16(&cur, key->len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_string(&cur, key)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_be16(&cur, value->len)) goto WRITE_ERR;
        if (!aws_byte_cursor_write_from_whole_string(&cur, value)) goto WRITE_ERR;
    }
    aws_array_list_clean_up(&elems);
    return AWS_OP_SUCCESS;

WRITE_ERR:
    aws_array_list_clean_up(&elems);
    aws_byte_buf_clean_up(output);
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
}

int aws_cryptosdk_context_deserialize(struct aws_allocator *alloc, struct aws_hash_table *enc_context, struct aws_byte_cursor *cursor) {
    aws_hash_table_clear(enc_context);

    if (cursor->len == 0) {
        return AWS_OP_SUCCESS;
    }

    uint16_t elem_count;
    if (!aws_byte_cursor_read_be16(cursor, &elem_count)) goto SHORT_BUF;
    if (!elem_count) return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);

    for (uint16_t i = 0; i < elem_count; i++) {
        uint16_t len;

        if (!aws_byte_cursor_read_be16(cursor, &len)) goto SHORT_BUF;
        struct aws_byte_cursor k_cursor = aws_byte_cursor_advance_nospec(cursor, len);
        if (!k_cursor.ptr) goto SHORT_BUF;

        if (!aws_byte_cursor_read_be16(cursor, &len)) goto SHORT_BUF;
        struct aws_byte_cursor v_cursor = aws_byte_cursor_advance_nospec(cursor, len);
        if (!v_cursor.ptr) goto SHORT_BUF;

        const struct aws_string *k = aws_string_new_from_array(alloc, k_cursor.ptr, k_cursor.len);
        const struct aws_string *v = aws_string_new_from_array(alloc, v_cursor.ptr, v_cursor.len);

        if (!k || !v || aws_hash_table_put(enc_context, k, (void *)v, NULL)) {
            aws_string_destroy((void *)k);
            aws_string_destroy((void *)v);
            goto RETHROW;
        }
    }

    return AWS_OP_SUCCESS;

SHORT_BUF:
    aws_raise_error(AWS_ERROR_SHORT_BUFFER);
RETHROW:
    aws_hash_table_clear(enc_context);
    return AWS_OP_ERR;
}
