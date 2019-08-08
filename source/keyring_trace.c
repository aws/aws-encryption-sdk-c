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
#include <aws/cryptosdk/private/keyring_trace.h>
#include <aws/cryptosdk/private/utils.h>

bool aws_cryptosdk_keyring_trace_is_valid(struct aws_array_list *trace) {
    if (!trace) {
        return false;
    }
    /* iterate over each record in the list */
    size_t num_records = aws_array_list_length(trace);
    bool is_valid      = aws_array_list_is_valid(trace);
    for (size_t idx = 0; idx < num_records; ++idx) {
        struct aws_cryptosdk_keyring_trace_record *record;
        if (!aws_array_list_get_at_ptr(trace, (void **)&record, idx)) {
            /* check if each record is valid */
            bool record_is_valid = aws_cryptosdk_keyring_trace_record_is_valid(record);
            is_valid &= record_is_valid;
        }
    }
    return is_valid;
}

bool aws_cryptosdk_keyring_trace_record_is_valid(struct aws_cryptosdk_keyring_trace_record *record) {
    if (!record) {
        return false;
    }
    bool wk_namespace_is_valid = aws_string_is_valid(record->wrapping_key_namespace);
    bool wk_name_is_valid      = aws_string_is_valid(record->wrapping_key_name);
    bool flags_is_valid        = record->flags;
    return wk_namespace_is_valid && wk_name_is_valid && flags_is_valid;
}

void aws_cryptosdk_keyring_trace_record_clean_up(struct aws_cryptosdk_keyring_trace_record *record) {
    AWS_FATAL_PRECONDITION(record != NULL);
    aws_string_destroy(record->wrapping_key_namespace);
    aws_string_destroy(record->wrapping_key_name);
    record->flags                  = 0;
    record->wrapping_key_namespace = record->wrapping_key_name = NULL;
    AWS_POSTCONDITION(record->flags == 0);
    AWS_POSTCONDITION(record->wrapping_key_name == NULL);
    AWS_POSTCONDITION(record->wrapping_key_namespace == NULL);
}

static inline int record_init_check(struct aws_cryptosdk_keyring_trace_record *record) {
    if (record->wrapping_key_namespace && record->wrapping_key_name) {
        return AWS_OP_SUCCESS;
    }
    aws_cryptosdk_keyring_trace_record_clean_up(record);
    return AWS_OP_ERR;
}

static int record_init_from_c_strs(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_keyring_trace_record *record,
    const char *wk_namespace,
    const char *wk_name,
    uint32_t flags) {
    record->flags                  = flags;
    record->wrapping_key_namespace = aws_string_new_from_c_str(alloc, wk_namespace);
    record->wrapping_key_name      = aws_string_new_from_c_str(alloc, wk_name);
    return record_init_check(record);
}

static int record_init_from_strings(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_keyring_trace_record *record,
    const struct aws_string *wk_namespace,
    const struct aws_string *wk_name,
    uint32_t flags) {
    record->flags                  = flags;
    record->wrapping_key_namespace = aws_cryptosdk_string_dup(alloc, wk_namespace);
    record->wrapping_key_name      = aws_cryptosdk_string_dup(alloc, wk_name);
    return record_init_check(record);
}

static int record_init_from_bufs(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_keyring_trace_record *record,
    const struct aws_byte_buf *wk_namespace,
    const struct aws_byte_buf *wk_name,
    uint32_t flags) {
    record->flags                  = flags;
    record->wrapping_key_namespace = aws_string_new_from_array(alloc, wk_namespace->buffer, wk_namespace->len);
    record->wrapping_key_name      = aws_string_new_from_array(alloc, wk_name->buffer, wk_name->len);
    return record_init_check(record);
}

static inline int push_record_onto_trace(
    struct aws_array_list *trace, struct aws_cryptosdk_keyring_trace_record *record) {
    int ret = aws_array_list_push_back(trace, (void *)record);
    if (ret) aws_cryptosdk_keyring_trace_record_clean_up(record);
    AWS_POSTCONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    return ret;
}

int aws_cryptosdk_keyring_trace_add_record(
    struct aws_allocator *alloc,
    struct aws_array_list *trace,
    const struct aws_string *wk_namespace,
    const struct aws_string *wk_name,
    uint32_t flags) {
    AWS_FATAL_PRECONDITION(alloc != NULL);
    AWS_FATAL_PRECONDITION(trace != NULL);
    AWS_FATAL_PRECONDITION(wk_namespace != NULL);
    AWS_FATAL_PRECONDITION(wk_name != NULL);
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    AWS_FATAL_PRECONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    struct aws_cryptosdk_keyring_trace_record record;
    int ret = record_init_from_strings(alloc, &record, wk_namespace, wk_name, flags);
    if (ret) return ret;
    return push_record_onto_trace(trace, &record);
}

int aws_cryptosdk_keyring_trace_add_record_c_str(
    struct aws_allocator *alloc,
    struct aws_array_list *trace,
    const char *wk_namespace,
    const char *wk_name,
    uint32_t flags) {
    AWS_FATAL_PRECONDITION(alloc != NULL);
    AWS_FATAL_PRECONDITION(trace != NULL);
    AWS_FATAL_PRECONDITION(wk_namespace != NULL);
    AWS_FATAL_PRECONDITION(wk_name != NULL);
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    AWS_FATAL_PRECONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    struct aws_cryptosdk_keyring_trace_record record;
    int ret = record_init_from_c_strs(alloc, &record, wk_namespace, wk_name, flags);
    if (ret) return ret;

    return push_record_onto_trace(trace, &record);
}

int aws_cryptosdk_keyring_trace_add_record_buf(
    struct aws_allocator *alloc,
    struct aws_array_list *trace,
    const struct aws_byte_buf *wk_namespace,
    const struct aws_byte_buf *wk_name,
    uint32_t flags) {
    AWS_FATAL_PRECONDITION(alloc != NULL);
    AWS_FATAL_PRECONDITION(trace != NULL);
    AWS_FATAL_PRECONDITION(wk_namespace != NULL);
    AWS_FATAL_PRECONDITION(wk_name != NULL);
    AWS_FATAL_PRECONDITION(aws_byte_buf_is_valid(wk_namespace));
    AWS_FATAL_PRECONDITION(aws_byte_buf_is_valid(wk_name));
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    AWS_FATAL_PRECONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    struct aws_cryptosdk_keyring_trace_record record;
    int ret = record_init_from_bufs(alloc, &record, wk_namespace, wk_name, flags);
    if (ret) return ret;

    return push_record_onto_trace(trace, &record);
}

int aws_cryptosdk_keyring_trace_init(struct aws_allocator *alloc, struct aws_array_list *trace) {
    // arbitrary starting point, list will resize as necessary
    AWS_FATAL_PRECONDITION(trace != NULL);
    AWS_FATAL_PRECONDITION(alloc != NULL);
    const int initial_size = 10;
    int r_val =
        aws_array_list_init_dynamic(trace, alloc, initial_size, sizeof(struct aws_cryptosdk_keyring_trace_record));
    if (r_val == AWS_OP_SUCCESS) {
        AWS_POSTCONDITION(aws_array_list_is_valid(trace));
        AWS_POSTCONDITION(trace->alloc == alloc);
        AWS_POSTCONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
        AWS_POSTCONDITION(trace->length == 0);
    }
    return r_val;
}

int aws_cryptosdk_keyring_trace_record_init_clone(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_keyring_trace_record *dest,
    const struct aws_cryptosdk_keyring_trace_record *src) {
    AWS_FATAL_PRECONDITION(alloc != NULL);
    AWS_FATAL_PRECONDITION(dest != NULL);
    AWS_FATAL_PRECONDITION(src != NULL);

    AWS_FATAL_PRECONDITION(aws_string_is_valid(src->wrapping_key_namespace));
    AWS_FATAL_PRECONDITION(aws_string_is_valid(src->wrapping_key_name));

    dest->wrapping_key_namespace = aws_cryptosdk_string_dup(alloc, src->wrapping_key_namespace);
    dest->wrapping_key_name      = aws_cryptosdk_string_dup(alloc, src->wrapping_key_name);
    if (record_init_check(dest)) {
        aws_cryptosdk_keyring_trace_record_clean_up(dest);
        AWS_POSTCONDITION(dest->flags == 0);
        AWS_POSTCONDITION(dest->wrapping_key_name == NULL);
        AWS_POSTCONDITION(dest->wrapping_key_namespace == NULL);
        return AWS_OP_ERR;
    }
    dest->flags = src->flags;
    AWS_POSTCONDITION(aws_string_eq(src->wrapping_key_namespace, dest->wrapping_key_namespace));
    AWS_POSTCONDITION(aws_string_eq(src->wrapping_key_name, dest->wrapping_key_name));
    AWS_POSTCONDITION(src->flags == dest->flags);
    return AWS_OP_SUCCESS;
}

static bool aws_cryptosdk_keyring_trace_record_eq(
    const struct aws_cryptosdk_keyring_trace_record *a, const struct aws_cryptosdk_keyring_trace_record *b) {
    return a->flags == b->flags && aws_string_eq(a->wrapping_key_namespace, b->wrapping_key_namespace) &&
           aws_string_eq(a->wrapping_key_name, b->wrapping_key_name);
}

bool aws_cryptosdk_keyring_trace_eq(const struct aws_array_list *a, const struct aws_array_list *b) {
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(a));
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(b));
    AWS_FATAL_PRECONDITION(a->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    AWS_FATAL_PRECONDITION(b->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    size_t num_records = aws_array_list_length(a);
    if (num_records != aws_array_list_length(b)) return false;

    struct aws_cryptosdk_keyring_trace_record *a_rec;
    struct aws_cryptosdk_keyring_trace_record *b_rec;
    for (size_t idx = 0; idx < num_records; ++idx) {
        if (aws_array_list_get_at_ptr(a, (void **)&a_rec, idx) || aws_array_list_get_at_ptr(b, (void **)&b_rec, idx)) {
            abort();
        }
        if (!aws_cryptosdk_keyring_trace_record_eq(a_rec, b_rec)) return false;
    }
    return true;
}

void aws_cryptosdk_keyring_trace_clear(struct aws_array_list *trace) {
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    AWS_FATAL_PRECONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    size_t num_records = aws_array_list_length(trace);
    for (size_t idx = 0; idx < num_records; ++idx) {
        struct aws_cryptosdk_keyring_trace_record *record;
        if (!aws_array_list_get_at_ptr(trace, (void **)&record, idx)) {
            aws_cryptosdk_keyring_trace_record_clean_up(record);
        }
    }
    aws_array_list_clear(trace);
}

void aws_cryptosdk_keyring_trace_clean_up(struct aws_array_list *trace) {
    AWS_FATAL_PRECONDITION(aws_cryptosdk_keyring_trace_is_valid(trace));
    AWS_FATAL_PRECONDITION(trace->item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    aws_cryptosdk_keyring_trace_clear(trace);
    aws_array_list_clean_up(trace);
}
