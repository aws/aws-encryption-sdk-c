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
#include <aws/cryptosdk/keyring_trace.h>

static inline void wrapping_key_clean_up(
    struct aws_cryptosdk_wrapping_key *wrapping_key) {
    aws_string_destroy(wrapping_key->name_space);
    aws_string_destroy(wrapping_key->name);
}

static inline int wrapping_key_init_check(
    struct aws_cryptosdk_wrapping_key *wrapping_key) {
    if (wrapping_key->name_space && wrapping_key->name) {
        return AWS_OP_SUCCESS;
    }
    wrapping_key_clean_up(wrapping_key);
    wrapping_key->name_space = wrapping_key->name = NULL;
    return AWS_OP_ERR;
}

static inline int wrapping_key_init_from_strings(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_wrapping_key *wrapping_key,
    const struct aws_string *name_space,
    const struct aws_string *name) {
    wrapping_key->name_space = aws_string_new_from_string(alloc, name_space);
    wrapping_key->name = aws_string_new_from_string(alloc, name);
    return wrapping_key_init_check(wrapping_key);
}

static inline int wrapping_key_init_from_c_strs(
    struct aws_allocator *alloc,
    struct aws_cryptosdk_wrapping_key *wrapping_key,
    const char *name_space,
    const char *name) {
    wrapping_key->name_space = aws_string_new_from_c_str(alloc, name_space);
    wrapping_key->name = aws_string_new_from_c_str(alloc, name);
    return wrapping_key_init_check(wrapping_key);
}

static inline int keyring_trace_add_item_base(
    struct aws_array_list *trace,
    struct aws_cryptosdk_keyring_trace_item *item,
    uint32_t flags) {
    item->flags = flags;
    int ret = aws_array_list_push_back(trace, (void *)item);
    if (ret) wrapping_key_clean_up(&item->wrapping_key);

    return ret;
}

int aws_cryptosdk_keyring_trace_add_item(struct aws_allocator *alloc,
                                         struct aws_array_list *trace,
                                         const struct aws_string *name_space,
                                         const struct aws_string *name,
                                         uint32_t flags) {
    struct aws_cryptosdk_keyring_trace_item item;
    int ret = wrapping_key_init_from_strings(alloc, &item.wrapping_key, name_space, name);
    if (ret) return ret;

    return keyring_trace_add_item_base(trace, &item, flags);
}

int aws_cryptosdk_keyring_trace_add_item_c_str(struct aws_allocator *alloc,
                                               struct aws_array_list *trace,
                                               const char *name_space,
                                               const char *name,
                                               uint32_t flags) {
    struct aws_cryptosdk_keyring_trace_item item;
    int ret = wrapping_key_init_from_c_strs(alloc, &item.wrapping_key, name_space, name);
    if (ret) return ret;

    return keyring_trace_add_item_base(trace, &item, flags);
}

int aws_cryptosdk_keyring_trace_init(struct aws_allocator *alloc, struct aws_array_list *trace) {
    const int initial_size = 10; // arbitrary starting point, list will resize as necessary
    return aws_array_list_init_dynamic(trace,
                                       alloc,
                                       initial_size,
                                       sizeof(struct aws_cryptosdk_keyring_trace_item));
}

void aws_cryptosdk_keyring_trace_clear(struct aws_array_list *trace) {
    size_t num_items = aws_array_list_length(trace);
    for (size_t idx = 0; idx < num_items; ++idx) {
        struct aws_cryptosdk_keyring_trace_item *item;
        if (!aws_array_list_get_at_ptr(trace, (void **)&item, idx)) {
            wrapping_key_clean_up(&item->wrapping_key);
        }
    }
    aws_array_list_clear(trace);
}

void aws_cryptosdk_keyring_trace_clean_up(struct aws_array_list *trace) {
    aws_cryptosdk_keyring_trace_clear(trace);
    aws_array_list_clean_up(trace);
}
