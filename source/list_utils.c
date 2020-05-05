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
#include <assert.h>
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/list_utils.h>
#include <aws/cryptosdk/private/keyring_trace.h>

int aws_cryptosdk_transfer_list(struct aws_array_list *dest, struct aws_array_list *src) {
    AWS_ERROR_PRECONDITION(src != dest);
    AWS_ERROR_PRECONDITION(aws_array_list_is_valid(dest));
    AWS_ERROR_PRECONDITION(aws_array_list_is_valid(src));
    AWS_ERROR_PRECONDITION(dest->item_size == src->item_size);

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

// allocator, dest, src
typedef int (*clone_item_fn)(struct aws_allocator *, void *, const void *);
typedef void (*clean_up_item_fn)(void *);

static int list_copy_all(
    struct aws_allocator *alloc,
    struct aws_array_list *dest,
    const struct aws_array_list *src,
    clone_item_fn cloner,
    clean_up_item_fn cleaner) {
    assert(dest->item_size == src->item_size);

    size_t initial_length = aws_array_list_length(dest);
    size_t src_length     = aws_array_list_length(src);
    int lasterr;

    /* You can do this with a variable length uint8_t array everywhere except Windows,
     * but Microsoft forces us to do an allocation here.
     */
    void *dest_item = aws_mem_acquire(alloc, dest->item_size);
    if (!dest_item) {
        return AWS_OP_ERR;
    }

    for (size_t i = 0; i < src_length; i++) {
        void *src_item;

        if (aws_array_list_get_at_ptr(src, &src_item, i)) {
            goto err;
        }

        if (cloner(alloc, dest_item, src_item)) {
            goto err;
        }

        if (aws_array_list_push_back(dest, dest_item)) {
            cleaner(dest_item);
            goto err;
        }
    }

    aws_mem_release(alloc, dest_item);
    return AWS_OP_SUCCESS;
err:
    aws_mem_release(alloc, dest_item);
    lasterr = aws_last_error();

    while (aws_array_list_length(dest) > initial_length) {
        void *dest_item_ptr;

        if (aws_array_list_get_at_ptr(dest, &dest_item_ptr, aws_array_list_length(dest) - 1)) {
            /*
             * We had elements at aws_array_list, but not anymore, it seems.
             * Someone must be mucking with the destination list from another thread;
             * abort before we do any more damage.
             */
            abort();
        }
        cleaner(dest_item_ptr);
        aws_array_list_pop_back(dest);
    }

    return aws_raise_error(lasterr);
}

int aws_cryptosdk_edk_list_copy_all(
    struct aws_allocator *alloc, struct aws_array_list *dest, const struct aws_array_list *src) {
    return list_copy_all(
        alloc, dest, src, (clone_item_fn)aws_cryptosdk_edk_init_clone, (clean_up_item_fn)aws_cryptosdk_edk_clean_up);
}

int aws_cryptosdk_keyring_trace_copy_all(
    struct aws_allocator *alloc, struct aws_array_list *dest, const struct aws_array_list *src) {
    return list_copy_all(
        alloc,
        dest,
        src,
        (clone_item_fn)aws_cryptosdk_keyring_trace_record_init_clone,
        (clean_up_item_fn)aws_cryptosdk_keyring_trace_record_clean_up);
}
