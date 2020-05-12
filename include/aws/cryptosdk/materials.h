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

#ifndef AWS_CRYPTOSDK_MATERIALS_H
#define AWS_CRYPTOSDK_MATERIALS_H

#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include <aws/common/array_list.h>
#include <aws/common/atomics.h>
#include <aws/common/byte_buf.h>
#include <aws/common/common.h>
#include <aws/common/hash_table.h>

#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/exports.h>
#include <aws/cryptosdk/header.h>
#include <aws/cryptosdk/keyring_trace.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cmm_kr_highlevel Materials providers
 *
 * The behavior of the encryption SDK is largely defined by two types of materials providers -
 * the Crypto Materials Managers (CMMs) and Keyrings. In order to perform an encryption or
 * decryption operation, the @ref session must be given a CMM, which will typically be configured
 * to delegate to one or more keyrings to perform the key wrapping or unwrapping operation.
 *
 * Broadly speaking, you can think of a keyring as defining the underlying keys used to encrypt
 * and decrypt (and therefore, who has access to the final message), while CMMs can perform
 * higher-level manipulations on the overall encrypt/decrypt operation (such as caching the
 * results of invoking the keyring).
 *
 * CMM and keyring objects are reference counted to make it easier to construct higher-level
 * CMMs or keyrings out of other primitives; in general, functions in the encryption SDK which
 * take a CMM or keyring as an argument will appropriately increment the reference count (and
 * decrement it when they no longer have a reference). When this reference count reaches zero,
 * the CMM or keyring will be destroyed.
 *
 * All CMMs and keyrings provided as built-ins are thread-safe with respect to the API they
 * expose to the session; however, any configuration APIs that are specific to the type of
 * CMM or keyring in question may not be thread safe (that is, you can't safely change the
 * configuration while using the CMM or keyring on another thread's session object).
 */

/**
 * @defgroup cmm_kr_lowlevel Low-level materials provider APIs
 *
 * This section contains low-level APIs of interest to developers of custom keyrings or CMMs.
 * @{
 */

// Note: Most of this file will be in the low-level section.
// To move something to the high-level section, use @ingroup cmm_kr_highlevel

/**
 * Base type for a Crypto Materials Manager. Unless you are writing your own CMM, you should
 * not create this struct directly; see @ref aws_cryptosdk_default_cmm_new for a CMM
 * that will suffice in most situations.
 *
 * Implementers of CMMs should embed this struct in their implementation-specific state structure,
 * and use @ref aws_cryptosdk_cmm_base_init to initialize its contents.
 */
struct aws_cryptosdk_cmm {
    struct aws_atomic_var refcount;
    const struct aws_cryptosdk_cmm_vt *vtable;
};

/**
 * Base type for a keyring. Unless you are writing your own keyrings, you should
 * not create this struct directly; see @ref kms_keyring or @ref raw_keyring for built-in keyring
 * implementations.
 *
 * Implementers of keyrings should embed this struct in their implementation-specific state structure,
 * and use @ref aws_cryptosdk_keyring_base_init to initialize its contents.
 */
struct aws_cryptosdk_keyring {
    struct aws_atomic_var refcount;
    const struct aws_cryptosdk_keyring_vt *vtable;
};

/**
 * Encryption request passed from the session to a CMM
 */
struct aws_cryptosdk_enc_request {
    struct aws_allocator *alloc;
    /**
     * The encryption context for this message. CMMs are permitted to modify this
     * hash table in order to inject additional keys or otherwise modify the encryption
     * context.
     */
    struct aws_hash_table *enc_ctx;
    /**
     * The session will initially call generate_enc_materials on the CMM
     * with a zero requested_alg; it's up to one of the CMMs in the chain to fill
     * this in before the keyring is invoked. In particular, the default CMM will
     * fill in the algorithm ID it has been configured with, unless a CMM before
     * the default CMM filled in a different algorithm ID.
     */
    enum aws_cryptosdk_alg_id requested_alg;
    /**
     * An upper-bound on the plaintext size to be encrypted (comes from @ref
     * aws_cryptosdk_session_set_message_bound or @ref
     * aws_cryptosdk_session_set_message_size). If no bound has been set,
     * this will be UINT64_MAX.
     */
    uint64_t plaintext_size;
};

/**
 * Materials returned from a CMM generate_enc_materials operation
 */
struct aws_cryptosdk_enc_materials {
    struct aws_allocator *alloc;
    struct aws_byte_buf unencrypted_data_key;
    /** Contains a trace of which wrapping keys took which actions in this request */
    struct aws_array_list keyring_trace;
    /** List of struct aws_cryptosdk_edk objects */
    struct aws_array_list encrypted_data_keys;
    /** Trailing signature context, or NULL if no trailing signature is needed for this algorithm */
    struct aws_cryptosdk_sig_ctx *signctx;
    enum aws_cryptosdk_alg_id alg;
};

/**
 * Decryption request passed from session to CMM
 */
struct aws_cryptosdk_dec_request {
    struct aws_allocator *alloc;
    const struct aws_hash_table *enc_ctx;
    struct aws_array_list encrypted_data_keys;
    enum aws_cryptosdk_alg_id alg;
};

/**
 * Decryption materials returned from CMM to session
 */
struct aws_cryptosdk_dec_materials {
    struct aws_allocator *alloc;
    struct aws_byte_buf unencrypted_data_key;
    /** Contains a trace of which wrapping keys took which actions in this request */
    struct aws_array_list keyring_trace;
    /** Trailing signature context, or NULL if no trailing signature is needed for this algorithm */
    struct aws_cryptosdk_sig_ctx *signctx;
    enum aws_cryptosdk_alg_id alg;
};

#ifndef AWS_CRYPTOSDK_DOXYGEN /* do not document internal macros */

/*
 * C99 standard dictates that "..." must have at least one argument behind it. Second arg of
 * _VF_CALL macros is always struct type, i.e., "cmm" or "keyring". These helper macros allow
 * us not to make struct_type a named argument, thus handling the case cleanly where there
 * are no more arguments.
 *
 * Note: We work around a VC++ preprocessor bug here. See https://stackoverflow.com/a/4750720
 */
#    define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(...) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_2((__VA_ARGS__, throwaway))
#    define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_2(args) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_3 args
#    define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_3(struct_type, ...) struct_type

#    define AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(...) AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_2((__VA_ARGS__, throwaway))
#    define AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_2(args) AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_3 args
#    define AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_3(struct_type, ...) const struct aws_cryptosdk_##struct_type

/**
 * Macro for virtual function calls that captures an integer return value. Checks that vt_size
 * is large enough and that pointer is non-null before attempting call. If checks fail, sets
 * AWS internal error to AWS_ERROR_UNIMPLEMENTED and returns the value of aws_raise_error(),
 * i.e., AWS_OP_ERR. Otherwise ret is set to return value of the virtual function call.
 *
 * Note that this depends on a naming convention of always using "cmm" or "keyring" as the
 * name of the pointer variable as the first argument of the virtual function in the inline
 * functions below which call this macro.
 */
#    define AWS_CRYPTOSDK_PRIVATE_VF_CALL(fn_name, ...)                                                          \
        int ret;                                                                                                 \
        do {                                                                                                     \
            AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *pbase =                                                \
                (AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *)AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(__VA_ARGS__);  \
            ptrdiff_t memb_offset = (const uint8_t *)&(pbase->vtable)->fn_name - (const uint8_t *)pbase->vtable; \
            if (memb_offset + sizeof((pbase->vtable)->fn_name) > (pbase->vtable)->vt_size ||                     \
                !(pbase->vtable)->fn_name) {                                                                     \
                return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);                                                 \
            }                                                                                                    \
            ret = (pbase->vtable)->fn_name(__VA_ARGS__);                                                         \
        } while (0)

/**
 * Macro for virtual function calls with no return value, e.g. destroy. Checks that vt_size is
 * large enough and that pointer is non-null before attempting call. If checks fail, sets error
 * code to AWS_ERROR_UNIMPLEMENTED and otherwise is a no-op.
 */
#    define AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(fn_name, ...)                                                \
        do {                                                                                                     \
            AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *pbase =                                                \
                (AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *)AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(__VA_ARGS__);  \
            ptrdiff_t memb_offset = (const uint8_t *)&(pbase->vtable)->fn_name - (const uint8_t *)pbase->vtable; \
            if (memb_offset + sizeof((pbase->vtable)->fn_name) > (pbase->vtable)->vt_size ||                     \
                !(pbase->vtable)->fn_name) {                                                                     \
                aws_raise_error(AWS_ERROR_UNIMPLEMENTED);                                                        \
            } else {                                                                                             \
                (pbase->vtable)->fn_name(__VA_ARGS__);                                                           \
            }                                                                                                    \
        } while (0)

/**
 * Internal function: Decrement a refcount; return true if the object should be destroyed.
 */
AWS_CRYPTOSDK_STATIC_INLINE bool aws_cryptosdk_private_refcount_down(struct aws_atomic_var *refcount) {
    /*
     * Memory ordering note: We must use release_acquire memory order here. Otherwise, we have the following race:
     *
     * Program order:
     *
     * Thread A:
     *   Release(obj) [if down() { free(obj) } ]
     *
     * Thread B:
     *   obj->foo = 1;
     *   Release(obj)
     *
     * Execution order:
     *
     * Thread B: down() -> false
     * Thread A: down() -> true
     * Thread A: free(obj)
     * Thread B: obj->foo = 1
     *
     * To prevent this we use release_acquire order. The release forbids any memory accesses sequenced-before the
     * atomic decrement of down() from being reordered later. This prevents thread B from reordering the obj->foo
     * access to come after the down(). The acquire ensures that the atomic decrements of down() calls correctly
     * synchronize-with one-another.
     */
    size_t old_count = aws_atomic_fetch_sub_explicit(refcount, 1, aws_memory_order_acq_rel);

    assert(old_count != 0);

    return old_count == 1;
}

/**
 * Internal function: Increment a refcount.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_private_refcount_up(struct aws_atomic_var *refcount) {
    /*
     * Memory ordering note: It is safe to use relaxed here. As an invariant, we assume that,
     * on entry, the thread has some guarantee that the refcount will not reach zero until after
     * refcount_up completes. As long as this guarantee is maintained until the next release barrier,
     * there is no problem; if we down() on the current thread, we achieve this explicitly. Otherwise,
     * if we communicate to some other thread that it is safe to release the reference, that communication
     * needs to be in release order, as it's effectively a proxy down() call, for the same reasons outlined
     * above in refcount_down().
     *
     * Since we've established that our initial reference won't be released until a release barrier
     * occurs, we are happy to let the increment be deferred until that barrier occurs. We're also
     * perfectly happy with a refcount increment happening logically earlier than expected, since this
     * won't cause the object to be freed unexpectedly.
     *
     * We also note that acquire order is not required: We know that the object itself is already valid
     * when we enter refcount_up - that is, refcount_up does not change the internal state of the object.
     * Therefore, it's okay if some code accesses the logical state of the object "before" the refcount
     * increment, so long as the object is not actually freed.
     */
    size_t old_count = aws_atomic_fetch_add_explicit(refcount, 1, aws_memory_order_relaxed);

    assert(old_count != 0 && old_count != SIZE_MAX);

    // Suppress unused variable warning when NDEBUG is set
    (void)old_count;
}
#endif  // AWS_CRYPTOSDK_DOXYGEN

/**
 * Virtual tables for CMM and keyring. Any implementation should declare a static instance of
 * this, and pass it to @ref aws_cryptosdk_cmm_base_init to initialize the base struct
 */
struct aws_cryptosdk_cmm_vt {
    /**
     * Always set to sizeof(struct aws_cryptosdk_cmm_vt).
     */
    size_t vt_size;
    /**
     * Identifier for debugging purposes only.
     */
    const char *name;
    /**
     * VIRTUAL FUNCTION: must implement unless it is a no-op. It is better to implement it as
     * a no-op function to avoid setting error code.
     */
    void (*destroy)(struct aws_cryptosdk_cmm *cmm);

    /**
     * VIRTUAL FUNCTION: must implement if used for encryption.
     */
    int (*generate_enc_materials)(
        struct aws_cryptosdk_cmm *cmm,
        struct aws_cryptosdk_enc_materials **output,
        struct aws_cryptosdk_enc_request *request);
    /**
     * VIRTUAL FUNCTION: must implement if used for decryption.
     */
    int (*decrypt_materials)(
        struct aws_cryptosdk_cmm *cmm,
        struct aws_cryptosdk_dec_materials **output,
        struct aws_cryptosdk_dec_request *request);
};

/**
 * Putting this here for now, until we get it merged into the atomics.h in c-common
 */
AWS_CRYPTOSDK_STATIC_INLINE bool aws_atomic_var_is_valid(const struct aws_atomic_var *var) {
    return AWS_OBJECT_PTR_IS_WRITABLE(var);
}

/**
 * Constant time check of data-structure invariants for struct aws_cryptosdk_cmm_vt
 */
AWS_CRYPTOSDK_STATIC_INLINE bool aws_cryptosdk_cmm_vtable_is_valid(const struct aws_cryptosdk_cmm_vt *vtable) {
    return AWS_OBJECT_PTR_IS_READABLE(vtable) && vtable->vt_size == sizeof(struct aws_cryptosdk_cmm_vt) &&
           aws_c_string_is_valid(vtable->name);
}

/**
 * Constant time check of data-structure invariants for struct aws_cryptosdk_cmm. Since implementations of the
 * cmm may add additional fields, they may define their own, specialized is_valid functions that use this as a base.
 */
AWS_CRYPTOSDK_STATIC_INLINE bool aws_cryptosdk_cmm_base_is_valid(const struct aws_cryptosdk_cmm *cmm) {
    return AWS_OBJECT_PTR_IS_WRITABLE(cmm) && aws_atomic_var_is_valid(&cmm->refcount) &&
           aws_atomic_load_int(&cmm->refcount) > 0 && aws_atomic_load_int(&cmm->refcount) <= SIZE_MAX &&
           aws_cryptosdk_cmm_vtable_is_valid(cmm->vtable);
}

/**
 * Initialize the base structure for a CMM. The implementation of a CMM needs to call this function to set up the
 * vtable and reference count. On return, the reference count is initialized to 1.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_cmm_base_init(
    struct aws_cryptosdk_cmm *cmm, const struct aws_cryptosdk_cmm_vt *vtable) {
    AWS_PRECONDITION(AWS_OBJECT_PTR_IS_WRITABLE(cmm));
    AWS_PRECONDITION(aws_cryptosdk_cmm_vtable_is_valid(vtable));
    cmm->vtable = vtable;
    aws_atomic_init_int(&cmm->refcount, 1);
    AWS_POSTCONDITION(aws_cryptosdk_cmm_base_is_valid(cmm));
}

/**
 * @ingroup cmm_kr_highlevel
 * Decrements the reference count on the CMM. If the new reference count is zero, the CMM is destroyed.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_cmm_release(struct aws_cryptosdk_cmm *cmm) {
    AWS_PRECONDITION(!cmm || aws_cryptosdk_cmm_base_is_valid(cmm));
    if (cmm && aws_cryptosdk_private_refcount_down(&cmm->refcount)) {
        AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(destroy, cmm);
    }
}

/**
 * @ingroup cmm_kr_highlevel
 * Increments the reference count on the CMM.
 */
AWS_CRYPTOSDK_STATIC_INLINE struct aws_cryptosdk_cmm *aws_cryptosdk_cmm_retain(struct aws_cryptosdk_cmm *cmm) {
    AWS_PRECONDITION(aws_cryptosdk_cmm_base_is_valid(cmm));
    AWS_PRECONDITION(AWS_ATOMIC_VAR_INTVAL(&cmm->refcount) < SIZE_MAX);
    aws_cryptosdk_private_refcount_up(&cmm->refcount);
    AWS_POSTCONDITION(aws_cryptosdk_cmm_base_is_valid(cmm));
    return cmm;
}

/**
 * Receives encryption request from user and attempts to generate encryption materials,
 * including an encrypted data key and a list of EDKs for doing encryption.
 *
 * On success returns AWS_OP_SUCCESS and allocates encryption materials object at address
 * pointed to by output.
 *
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets
 * internal AWS error code.
 */
AWS_CRYPTOSDK_STATIC_INLINE int aws_cryptosdk_cmm_generate_enc_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_enc_materials **output,
    struct aws_cryptosdk_enc_request *request) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(generate_enc_materials, cmm, output, request);
    return ret;
}

/**
 * Receives decryption request from user and attempts to get decryption materials.
 *
 * On success returns AWS_OP_SUCCESS and allocates decryption materials object at address
 * pointed to by output.
 *
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets
 * internal AWS error code.
 */
AWS_CRYPTOSDK_STATIC_INLINE int aws_cryptosdk_cmm_decrypt_materials(
    struct aws_cryptosdk_cmm *cmm,
    struct aws_cryptosdk_dec_materials **output,
    struct aws_cryptosdk_dec_request *request) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(decrypt_materials, cmm, output, request);
    return ret;
}

struct aws_cryptosdk_keyring_vt {
    /**
     * Always set to sizeof(struct aws_cryptosdk_keyring_vt).
     */
    size_t vt_size;
    /**
     * Identifier for debugging purposes only.
     */
    const char *name;
    /**
     * VIRTUAL FUNCTION: must implement unless it is a no-op. It is better to implement it as
     * a no-op function to avoid setting error code.
     */
    void (*destroy)(struct aws_cryptosdk_keyring *keyring);

    /**
     * VIRTUAL FUNCTION: must implement if used for encryption.
     *
     * When the buffer for the unencrypted data key is not NULL at the time of the call, it
     * must not be changed by callee. All buffers for EDKs pushed onto the list must be in a
     * valid state, which means either that they are set to all zeroes or that they have been
     * initialized using one of the byte buffer initialization functions. This assures proper
     * clean up and serialization.
     */
    int (*on_encrypt)(
        struct aws_cryptosdk_keyring *keyring,
        struct aws_allocator *request_alloc,
        struct aws_byte_buf *unencrypted_data_key,
        struct aws_array_list *keyring_trace,
        struct aws_array_list *edks,
        const struct aws_hash_table *enc_ctx,
        enum aws_cryptosdk_alg_id alg);

    /**
     * VIRTUAL FUNCTION: must implement if used for decryption.
     *
     * Implementations must properly initialize the unencrypted data key buffer when an
     * EDK is decrypted and leave the unencrypted data key buffer pointer set to NULL
     * when no EDK is decrypted. Implementations should return AWS_OP_SUCCESS regardless
     * of whether the unencrypted data key is recovered, except in cases of internal errors.
     */
    int (*on_decrypt)(
        struct aws_cryptosdk_keyring *keyring,
        struct aws_allocator *request_alloc,
        struct aws_byte_buf *unencrypted_data_key,
        struct aws_array_list *keyring_trace,
        const struct aws_array_list *edks,
        const struct aws_hash_table *enc_ctx,
        enum aws_cryptosdk_alg_id alg);
};

/**
 * Constant time check of data-structure invariants for struct aws_cryptosdk_keyring_vt.
 */
AWS_CRYPTOSDK_STATIC_INLINE bool aws_cryptosdk_keyring_vt_is_valid(const struct aws_cryptosdk_keyring_vt *vtable) {
    return AWS_OBJECT_PTR_IS_READABLE(vtable) && aws_c_string_is_valid(vtable->name) &&
           /* Always set to sizeof(struct aws_cryptosdk_keyring_vt). */
           (vtable->vt_size == sizeof(struct aws_cryptosdk_keyring_vt));
}

/**
 * Constant time check of data-structure invariants for struct aws_cryptosdk_keyring.
 */
AWS_CRYPTOSDK_STATIC_INLINE bool aws_cryptosdk_keyring_is_valid(const struct aws_cryptosdk_keyring *keyring) {
    return AWS_OBJECT_PTR_IS_READABLE(keyring) && aws_atomic_var_is_valid(&keyring->refcount) &&
           aws_atomic_load_int(&keyring->refcount) > 0 && aws_atomic_load_int(&keyring->refcount) <= SIZE_MAX &&
           (keyring->vtable == NULL || aws_cryptosdk_keyring_vt_is_valid(keyring->vtable));
}

/**
 * Initialize the base structure for a keyring. The implementation of a keyring needs to call this function
 * to set up the vtable and reference count. On return, the reference count is initialized to 1.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_keyring_base_init(
    struct aws_cryptosdk_keyring *keyring, const struct aws_cryptosdk_keyring_vt *vtable) {
    AWS_PRECONDITION(keyring != NULL);
    AWS_PRECONDITION(vtable == NULL || aws_cryptosdk_keyring_vt_is_valid(vtable));
    keyring->vtable = vtable;
    aws_atomic_init_int(&keyring->refcount, 1);
}

/**
 * @ingroup cmm_kr_highlevel
 * Decrements the reference count on the keyring; if the new reference count is zero, the keyring is destroyed.
 */
AWS_CRYPTOSDK_STATIC_INLINE void aws_cryptosdk_keyring_release(struct aws_cryptosdk_keyring *keyring) {
    if (keyring && aws_cryptosdk_private_refcount_down(&keyring->refcount)) {
        AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(destroy, keyring);
    }
}

/**
 * @ingroup cmm_kr_highlevel
 * Increments the reference count on the keyring.
 */
AWS_CRYPTOSDK_STATIC_INLINE struct aws_cryptosdk_keyring *aws_cryptosdk_keyring_retain(
    struct aws_cryptosdk_keyring *keyring) {
    aws_cryptosdk_private_refcount_up(&keyring->refcount);
    return keyring;
}

/**
 * If byte buffer for unencrypted_data_key is already allocated, this makes zero or more
 * encrypted data keys which decrypt to that data key and pushes them onto the EDK list.
 *
 * If byte buffer for unencrypted_data_key is not already allocated, this may make a new
 * data key, allocating the buffer and putting the data key into that buffer. It also makes
 * zero or more encrypted data keys which decrypt to that data key and pushes them onto
 * the EDK list.
 *
 * On success (1) AWS_OP_SUCCESS is returned, (2) if the unencrypted_data_key buffer was
 * previously allocated, it will be unchanged, (3) if the unencrypted_data_key buffer was
 * not previously allocated, it may now be allocated, (4) zero or more EDKS will be
 * appended to the list of EDKS.
 *
 * On failure AWS_OP_ERR is returned, an internal AWS error code is set.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_keyring_on_encrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg);

/**
 * The KR attempts to find one of the EDKs to decrypt.
 *
 * On success AWS_OP_SUCCESS will be returned. This does not necessarily mean that the
 * data key will be decrypted, as it is normal behavior that a particular KR may not
 * find an EDK that it can decrypt. To determine whether the data key was decrypted,
 * check unencrypted_data_key.buffer. If the data key was not decrypted, that pointer
 * will be set to NULL. If the data key was decrypted, that pointer will point to the
 * bytes of the key.
 *
 * On internal failure, AWS_OP_ERR will be returned and an error code will be set.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_keyring_on_decrypt(
    struct aws_cryptosdk_keyring *keyring,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    const struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg);

/**
 * Allocates a new encryption materials object, including allocating memory to the list
 * of EDKs. The list of EDKs will be empty and no memory will be allocated to any byte
 * buffers in that list, nor will memory be allocated to the unencrypted data key buffer.
 *
 * On failure, returns NULL and an error code will be set.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_enc_materials *aws_cryptosdk_enc_materials_new(
    struct aws_allocator *alloc, enum aws_cryptosdk_alg_id alg);

/**
 * Deallocates all memory associated with the encryption materials object including the
 * object itself. All keys in the materials will have their associated memory also
 * deallocated, but make sure that they have been initialized properly per the comments
 * on aws_cryptosdk_keyring_generate_data_key.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_enc_materials_destroy(struct aws_cryptosdk_enc_materials *enc_mat);

/**
 * Allocates a new decryption materials object. Note that no memory will be allocated to
 * the byte buffer for  the unencrypted data key. That will only be allocated when an EDK
 * is decrypted.
 *
 * On failure, returns NULL and an internal AWS error code is set.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_dec_materials *aws_cryptosdk_dec_materials_new(
    struct aws_allocator *alloc, enum aws_cryptosdk_alg_id alg);

/**
 * Deallocates all memory associated with the decryption materials object including the
 * object itself and the unencrypted data key it is holding, if an EDK has been decrypted
 * successfully.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_dec_materials_destroy(struct aws_cryptosdk_dec_materials *dec_mat);

#ifdef __cplusplus
}
#endif

/** @} */  // doxygen group cmm_kr_lowlevel

#endif  // AWS_CRYPTOSDK_MATERIALS_H
