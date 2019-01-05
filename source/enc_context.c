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
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/enc_context.h>
#include <aws/cryptosdk/private/utils.h>

#include <aws/common/byte_buf.h>

int aws_cryptosdk_enc_context_init(struct aws_allocator *alloc, struct aws_hash_table *enc_context) {
    size_t initial_size = 10;  // arbitrary starting point, will resize as necessary
    return aws_hash_table_init(
        enc_context,
        alloc,
        initial_size,
        aws_hash_string,
        aws_hash_callback_string_eq,
        aws_hash_callback_string_destroy,
        aws_hash_callback_string_destroy);
}

int aws_cryptosdk_context_size(size_t *size, const struct aws_hash_table *enc_context) {
    size_t serialized_len = 2;  // First two bytes are the number of k-v pairs
    size_t entry_count    = 0;

    for (struct aws_hash_iter iter = aws_hash_iter_begin(enc_context); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        entry_count++;

        if (entry_count > UINT16_MAX) {
            return aws_raise_error(AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED);
        }

        const struct aws_string *key   = iter.element.key;
        const struct aws_string *value = iter.element.value;
        serialized_len += 2 /* key length */ + key->len + 2 /* value length */ + value->len;

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

int aws_cryptosdk_context_serialize(
    struct aws_allocator *alloc, struct aws_byte_buf *output, const struct aws_hash_table *enc_context) {
    size_t length;
    if (aws_cryptosdk_context_size(&length, enc_context)) {
        return AWS_OP_ERR;
    }

    if (output->capacity < length) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (length == 0) {
        // Empty encryption context
        return AWS_OP_SUCCESS;
    }

    size_t num_elems = aws_hash_table_get_entry_count(enc_context);

    struct aws_array_list elems;
    if (aws_cryptosdk_hash_elems_array_init(alloc, &elems, enc_context)) return AWS_OP_ERR;

    aws_array_list_sort(&elems, aws_cryptosdk_compare_hash_elems_by_key_string);

    if (!aws_byte_buf_write_be16(output, (uint16_t)num_elems)) goto WRITE_ERR;

    for (size_t idx = 0; idx < num_elems; ++idx) {
        struct aws_hash_element elem;
        if (aws_array_list_get_at(&elems, (void *)&elem, idx)) {
            aws_array_list_clean_up(&elems);
            return AWS_OP_ERR;
        }
        const struct aws_string *key   = (const struct aws_string *)elem.key;
        const struct aws_string *value = (const struct aws_string *)elem.value;
        if (!aws_byte_buf_write_be16(output, (uint16_t)key->len)) goto WRITE_ERR;
        if (!aws_byte_buf_write_from_whole_string(output, key)) goto WRITE_ERR;
        if (!aws_byte_buf_write_be16(output, (uint16_t)value->len)) goto WRITE_ERR;
        if (!aws_byte_buf_write_from_whole_string(output, value)) goto WRITE_ERR;
    }
    aws_array_list_clean_up(&elems);
    return AWS_OP_SUCCESS;

WRITE_ERR:
    aws_array_list_clean_up(&elems);
    aws_byte_buf_clean_up(output);
    return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
}

int aws_cryptosdk_context_deserialize(
    struct aws_allocator *alloc, struct aws_hash_table *enc_context, struct aws_byte_cursor *cursor) {
    aws_cryptosdk_enc_context_clear(enc_context);

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

        struct aws_string *k = aws_string_new_from_array(alloc, k_cursor.ptr, k_cursor.len);
        struct aws_string *v = aws_string_new_from_array(alloc, v_cursor.ptr, v_cursor.len);

        if (!k || !v || aws_hash_table_put(enc_context, k, (void *)v, NULL)) {
            aws_string_destroy(k);
            aws_string_destroy(v);
            goto RETHROW;
        }
    }

    return AWS_OP_SUCCESS;

SHORT_BUF:
    aws_raise_error(AWS_ERROR_SHORT_BUFFER);
RETHROW:
    aws_cryptosdk_enc_context_clear(enc_context);
    return AWS_OP_ERR;
}

static struct aws_string *clone_or_reuse_string(struct aws_allocator *allocator, const struct aws_string *str) {
    if (str->allocator == NULL) {
        /*
         * Since the string cannot be deallocated, we assume that it
         * will remain valid for the lifetime of the application
         */
        return (struct aws_string *)str;
    }

    return aws_string_new_from_array(allocator, aws_string_bytes(str), str->len);
}

int aws_cryptosdk_enc_context_clone(
    struct aws_allocator *alloc, struct aws_hash_table *dest, const struct aws_hash_table *src) {
    /* First, scan the destination for keys that don't belong, and remove them */
    for (struct aws_hash_iter iter = aws_hash_iter_begin(dest); !aws_hash_iter_done(&iter); aws_hash_iter_next(&iter)) {
        struct aws_hash_element *src_elem = NULL;

        /* We don't need to check for an error return as we can just look at src_elem */
        aws_hash_table_find(src, iter.element.key, &src_elem);

        if (src_elem == NULL) {
            aws_hash_iter_delete(&iter, true);
        }
    }

    /* Next, iterate src and ensure that the destination is consistent */
    for (struct aws_hash_iter iter = aws_hash_iter_begin(src); !aws_hash_iter_done(&iter); aws_hash_iter_next(&iter)) {
        struct aws_hash_element *dest_elem = NULL;

        /*
         * We don't use _create here as we might not be able to reuse the key as-is, and want to avoid duping it
         * if it's already in the destination hash table.
         */
        aws_hash_table_find(dest, iter.element.key, &dest_elem);

        if (dest_elem && !aws_string_eq(dest_elem->value, iter.element.value)) {
            /* The key was present; only the value needs to be updated */
            struct aws_string *value = clone_or_reuse_string(alloc, iter.element.value);

            if (!value) {
                return AWS_OP_ERR;
            }

            aws_string_destroy(dest_elem->value);
            dest_elem->value = value;
        } else if (!dest_elem) {
            /* A new element needs to be created, with a copy of the key and value */
            struct aws_string *key   = clone_or_reuse_string(alloc, iter.element.key);
            struct aws_string *value = clone_or_reuse_string(alloc, iter.element.value);

            if (!key || !value || aws_hash_table_put(dest, key, value, NULL)) {
                aws_string_destroy(key);
                aws_string_destroy(value);

                return AWS_OP_ERR;
            }
        } else {
            /* Key and value matched; no change needed */
        }
    }

    return AWS_OP_SUCCESS;
}
