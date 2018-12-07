/* Licensed under the Apache License, Version 2.0 (the "License"). You may not use
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
#include <aws/cryptosdk/utils.h>
#include <aws/cryptosdk/private/utils.h>
#include <assert.h>

int aws_cryptosdk_compare_hash_elems_by_key_string(const void * elem_a, const void * elem_b) {
    const struct aws_hash_element * a = (const struct aws_hash_element *)elem_a;
    const struct aws_hash_element * b = (const struct aws_hash_element *)elem_b;
    const struct aws_string * key_a = (const struct aws_string *)a->key;
    const struct aws_string * key_b = (const struct aws_string *)b->key;
    return aws_string_compare(key_a, key_b);
}

int aws_cryptosdk_hash_elems_array_init(struct aws_allocator * alloc,
                                        struct aws_array_list * elems,
                                        const struct aws_hash_table * map) {
    size_t entry_count = aws_hash_table_get_entry_count(map);
    if (aws_array_list_init_dynamic(elems, alloc, entry_count, sizeof(struct aws_hash_element))) {
        return AWS_OP_ERR;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(map);
         !aws_hash_iter_done(&iter); aws_hash_iter_next(&iter)) {
        if (aws_array_list_push_back(elems, (void **) &iter.element)) {
            aws_array_list_clean_up(elems);
            return AWS_OP_ERR;
        }
    }
    assert(aws_array_list_length(elems) == entry_count);
    return AWS_OP_SUCCESS;
}

struct aws_string *aws_cryptosdk_string_dup(struct aws_allocator *alloc, const struct aws_string *str) {
    if (str->allocator) return aws_string_new_from_string(alloc, str);
    return (struct aws_string *)str;
}

int aws_cryptosdk_transfer_list(struct aws_array_list *dest, struct aws_array_list *src) {
    size_t src_len = aws_array_list_length(src);
    for (size_t src_idx = 0; src_idx < src_len; ++src_idx) {
        void *item_ptr;
        if (aws_array_list_get_at_ptr(src, &item_ptr, src_idx)) return AWS_OP_ERR;
        if (aws_array_list_push_back(dest, item_ptr)) return AWS_OP_ERR;
    }
    /* This clear is important. It does not free any memory, but it resets the length of the
     * source list to zero, so that the buffers or strings in its list elements will NOT get
     * freed when the list gets cleaned up. We do not want to free those buffers, because the
     * elements that were transferred to the new list were shallow copies using the same buffers
     * or strings.
     */
    aws_array_list_clear(src);
    return AWS_OP_SUCCESS;
}
