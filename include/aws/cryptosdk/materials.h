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
#include <stdint.h>
#include <limits.h>

#include <aws/common/common.h>
#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/atomics.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/header.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Base types for CMM and KR: Concrete implementations will create their own structs, which
 * must have this structure as the first member, and cast pointers accordingly. See
 * default_cmm.[ch] for an example of this.
 */
struct aws_cryptosdk_cmm {
    struct aws_atomic_var refcount;
    const struct aws_cryptosdk_cmm_vt *vtable;
};

struct aws_cryptosdk_keyring {
    struct aws_atomic_var refcount;
    const struct aws_cryptosdk_keyring_vt *vtable;
};

struct aws_cryptosdk_edk {
    struct aws_byte_buf provider_id;
    struct aws_byte_buf provider_info;
    struct aws_byte_buf enc_data_key;
};

/*
 * TODO: Private key stuff is needed for trailing signature.
 */
struct aws_cryptosdk_private_key {
    //FIXME: implement
    int x; // just putting something here for now to avoid warnings
};

struct aws_cryptosdk_public_key {
    //FIXME: implement
    int x; // just putting something here for now to avoid warnings
};

struct aws_cryptosdk_key_pair {
    struct aws_cryptosdk_private_key private_key;
    struct aws_cryptosdk_public_key public_key;
};

struct aws_cryptosdk_encryption_request {
    struct aws_allocator * alloc;
    struct aws_hash_table * enc_context;
    enum aws_cryptosdk_alg_id requested_alg;
    uint64_t plaintext_size;
};

struct aws_cryptosdk_encryption_materials {
    struct aws_allocator * alloc;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_array_list encrypted_data_keys; // list of struct aws_cryptosdk_edk objects
    struct aws_hash_table * enc_context;
    struct aws_cryptosdk_key_pair trailing_signature_key_pair;
    enum aws_cryptosdk_alg_id alg;
};

struct aws_cryptosdk_decryption_request {
    struct aws_allocator * alloc;
    struct aws_hash_table * enc_context;
    struct aws_array_list encrypted_data_keys;
    enum aws_cryptosdk_alg_id alg;
};

struct aws_cryptosdk_decryption_materials {
    struct aws_allocator * alloc;
    struct aws_byte_buf unencrypted_data_key;
    struct aws_cryptosdk_public_key trailing_signature_key;
    enum aws_cryptosdk_alg_id alg;
};

/*
 * C99 standard dictates that "..." must have at least one argument behind it. Second arg of _VF_CALL macros is always struct
 * type, i.e., "cmm" or "keyring". These helper macros allow us not to make struct_type a named argument, thus handling the
 * case cleanly where there are no more arguments.
 *
 * Note: We work around a VC++ preprocessor bug here. See https://stackoverflow.com/a/4750720
 */
#define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(...) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_2((__VA_ARGS__, throwaway))
#define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_2(args) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_3 args
#define AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME_3(struct_type, ...) struct_type

#define AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(...) AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_2((__VA_ARGS__, throwaway))
#define AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_2(args) AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_3 args
#define AWS_CRYPTOSDK_PRIVATE_BASE_TYPE_3(struct_type, ...) const struct aws_cryptosdk_ ## struct_type

/**
 * Macro for virtual function calls that return an integer error code. Checks that vt_size is large enough and that pointer is
 * non-null before attempting call. If checks fail, sets AWS internal error to AWS_ERROR_UNIMPLEMENTED
 * and returns the return value of aws_raise_error(), i.e., AWS_OP_ERR.
 *
 * Note that this depends on a naming convention of always using "cmm" or "keyring" as the name of the pointer variable
 * as the first argument of the virtual function in the inline functions below which call this macro.
 */
#define AWS_CRYPTOSDK_PRIVATE_VF_CALL(fn_name, ...) \
    do { \
        AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *pbase = \
            (AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(__VA_ARGS__); \
        ptrdiff_t memb_offset = (const uint8_t *)&(pbase->vtable)->fn_name - (const uint8_t *)pbase->vtable; \
        if (memb_offset + sizeof((pbase->vtable)->fn_name) > (pbase->vtable)->vt_size || !(pbase->vtable)->fn_name) { \
            return aws_raise_error(AWS_ERROR_UNIMPLEMENTED); \
        } \
        return (pbase->vtable)->fn_name(__VA_ARGS__); \
    } while (0)

/**
 * Macro for virtual function calls with no return value, e.g. destroy. Checks that vt_size is large enough and that pointer is
 * non-null before attempting call. If checks fail, sets AWS internal error to AWS_ERROR_UNIMPLEMENTED
 * and otherwise is a no-op.
 */
#define AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(fn_name, ...) \
    do { \
        AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *pbase = \
            (AWS_CRYPTOSDK_PRIVATE_BASE_TYPE(__VA_ARGS__) *) AWS_CRYPTOSDK_PRIVATE_STRUCT_NAME(__VA_ARGS__); \
        ptrdiff_t memb_offset = (const uint8_t *)&(pbase->vtable)->fn_name - (const uint8_t *)pbase->vtable; \
        if (memb_offset + sizeof((pbase->vtable)->fn_name) > (pbase->vtable)->vt_size || !(pbase->vtable)->fn_name) { \
            aws_raise_error(AWS_ERROR_UNIMPLEMENTED); \
        } else { \
            (pbase->vtable)->fn_name(__VA_ARGS__); \
        } \
    } while (0)

/**
 * Internal function: Decrement a refcount; return true if the object should be destroyed.
 */
static inline bool aws_cryptosdk_private_refcount_down(struct aws_atomic_var *refcount) {
    size_t old_count = aws_atomic_fetch_sub_explicit(refcount, 1, aws_memory_order_relaxed);

    assert(old_count != 0);

    return old_count == 1;
}

/**
 * Internal function: Increment a refcount.
 */
static inline void aws_cryptosdk_private_refcount_up(struct aws_atomic_var *refcount) {
    size_t old_count = aws_atomic_fetch_add_explicit(refcount, 1, aws_memory_order_relaxed);

    assert(old_count != 0 && old_count != SIZE_MAX);

    // Suppress unused variable warning when NDEBUG is set
    (void)old_count;
}

/**
 * Virtual tables for CMM and keyring. Any implementation should declare a static instance of this,
 * and the first element of the CMM or keyring struct should be a pointer to that static virtual table.
 */
struct aws_cryptosdk_cmm_vt {
    /**
     * Always set to sizeof(struct aws_cryptosdk_cmm_vt).
     */
    size_t vt_size;
    /**
     * Identifier for debugging purposes only.
     */
    const char * name;
    /**
     * VIRTUAL FUNCTION: must implement unless it is a no-op. It is better to implement it as
     * a no-op function to avoid setting error code.
     */
    void (*destroy)(struct aws_cryptosdk_cmm * cmm);

    /**
     * VIRTUAL FUNCTION: must implement if used for encryption.
     */
    int (*generate_encryption_materials)(struct aws_cryptosdk_cmm * cmm,
                                         struct aws_cryptosdk_encryption_materials ** output,
                                         struct aws_cryptosdk_encryption_request * request);
    /**
     * VIRTUAL FUNCTION: must implement if used for decryption.
     */
    int (*decrypt_materials)(struct aws_cryptosdk_cmm * cmm,
                             struct aws_cryptosdk_decryption_materials ** output,
                             struct aws_cryptosdk_decryption_request * request);
};

/**
 * Initialize the base structure for a CMM. This should be called by the /implementation/ of a CMM, to set up the
 * vtable and reference count.
 */
static inline void aws_cryptosdk_cmm_base_init(struct aws_cryptosdk_cmm * cmm, const struct aws_cryptosdk_cmm_vt *vtable) {
    cmm->vtable = vtable;
    aws_atomic_init_int(&cmm->refcount, 1);
}

/**
 * Decrements the reference count on the CMM; if the new reference count is zero, the CMM is destroyed.
 */
static inline void aws_cryptosdk_cmm_release(struct aws_cryptosdk_cmm * cmm) {
    if (cmm && aws_cryptosdk_private_refcount_down(&cmm->refcount)) {
        AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(destroy, cmm);
    }
}

/**
 * Increments the reference count on the cmm.
 */
static inline struct aws_cryptosdk_cmm *aws_cryptosdk_cmm_retain(struct aws_cryptosdk_cmm * cmm) {
    aws_cryptosdk_private_refcount_up(&cmm->refcount);
    return cmm;
}

/**
 * Receives encryption request from user and attempts to generate encryption materials, including an encrypted data key
 * and a set of EDKs for doing an encryption.
 *
 * On success returns AWS_OP_SUCCESS and allocates encryption materials object at address pointed to by output.
 *
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets internal AWS error code.
 */
static inline int aws_cryptosdk_cmm_generate_encryption_materials(
    struct aws_cryptosdk_cmm * cmm,
    struct aws_cryptosdk_encryption_materials ** output,
    struct aws_cryptosdk_encryption_request * request) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(generate_encryption_materials, cmm, output, request);
}

/**
 * Receives decryption request from user and attempts to get decryption materials by decrypting an EDK.
 *
 * On success returns AWS_OP_SUCCESS and allocates decryption materials object at address pointed to by output.
 *
 * On failure returns AWS_OP_ERR, sets address pointed to by output to NULL, and sets internal AWS error code.
 */
static inline int aws_cryptosdk_cmm_decrypt_materials(
    struct aws_cryptosdk_cmm * cmm,
    struct aws_cryptosdk_decryption_materials ** output,
    struct aws_cryptosdk_decryption_request * request) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(decrypt_materials, cmm, output, request);
}

struct aws_cryptosdk_keyring_vt {
    /**
     * Always set to sizeof(struct aws_cryptosdk_keyring_vt).
     */
    size_t vt_size;
    /**
     * Identifier for debugging purposes only.
     */
    const char * name;
    /**
     * VIRTUAL FUNCTION: must implement unless it is a no-op. It is better to implement it as
     * a no-op function to avoid setting error code.
     */
    void (*destroy)(struct aws_cryptosdk_keyring * keyring);
    /**
     * VIRTUAL FUNCTION: must implement if used for data key generation. If this is the only KR
     * and this is not implemented, encryption will not be possible.
     *
     * Implementations should treat the unencrypted_data_key and encrypted_data_keys elements of the encryption
     * materials as outputs and should not modify any other elements. They should consider the array list
     * at encrypted_data_keys to already be initialized and should append the EDK(s) they generate to that list.
     *
     * Implementations must also properly initialize the byte buffers of the unencrypted data key
     * and the EDK which it appends onto the list. The buffer for the unencrypted data key MUST be used.
     * Buffers for the EDK may or may not be used, but any buffers which are not used must have their
     * allocators set to NULL and lengths set to zero. This assures that both clean up and serialization
     * will function correctly.
     */
    int (*generate_data_key)(struct aws_cryptosdk_keyring * keyring,
                             struct aws_cryptosdk_encryption_materials * enc_mat);
    /**
     * VIRTUAL FUNCTION: must implement if used for encryption, except when it is the only KR.
     *
     * Implementations should treat only the encrypted_data_keys element of the encryption materials as output
     * and should not modify any other elements. They should consider the array list at encrypted_data_keys to
     * already be initialized and should append the EDK(s) they generate to that list.
     *
     * Implementations must also properly initialize the EDK which is appended to the list as explained in the
     * comments on generate_data_key above.
     */
    int (*encrypt_data_key)(struct aws_cryptosdk_keyring * keyring,
                            struct aws_cryptosdk_encryption_materials * enc_mat);

    /**
     * VIRTUAL FUNCTION: must implement if used for decryption.
     *
     * Implementations should treat only the unencrypted_data_key element of the decryption materials as output
     * and should not modify any other elements. Implementations must properly initialize the unencrypted data
     * key buffer when an EDK is decrypted and leave the unencrypted data key buffer pointer set to NULL when
     * no EDK is decrypted.
     */
    int (*decrypt_data_key)(struct aws_cryptosdk_keyring * keyring,
                            struct aws_cryptosdk_decryption_materials * dec_mat,
                            const struct aws_cryptosdk_decryption_request * request);
};

/**
 * Initialize the base structure for a keyring. This should be called by the /implementation/ of a keyring, to set up the
 * vtable and reference count.
 */
static inline void aws_cryptosdk_keyring_base_init(struct aws_cryptosdk_keyring * keyring, const struct aws_cryptosdk_keyring_vt *vtable) {
    keyring->vtable = vtable;
    aws_atomic_init_int(&keyring->refcount, 1);
}

/**
 * Decrements the reference count on the keyring; if the new reference count is zero, the keyring is destroyed.
 */
static inline void aws_cryptosdk_keyring_release(struct aws_cryptosdk_keyring * keyring) {
    if (keyring && aws_cryptosdk_private_refcount_down(&keyring->refcount)) {
        AWS_CRYPTOSDK_PRIVATE_VF_CALL_NO_RETURN(destroy, keyring);
    }
}

/**
 * Increments the reference count on the keyring.
 */
static inline struct aws_cryptosdk_keyring *aws_cryptosdk_keyring_retain(struct aws_cryptosdk_keyring * keyring) {
    aws_cryptosdk_private_refcount_up(&keyring->refcount);
    return keyring;
}

/**
 * The KR attempts to generate a new data key, and returns it in both unencrypted and encrypted form.
 * Encryption materials should have already been initialized.
 *
 * On success (1) AWS_OP_SUCCESS is returned, (2) the unencrypted data key buffer will contain the raw
 * bytes of the data key, and (3) one or more EDKs will be appended onto the list of EDKs.
 *
 * On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
 */
static inline int aws_cryptosdk_keyring_generate_data_key(
    struct aws_cryptosdk_keyring * keyring,
    struct aws_cryptosdk_encryption_materials * enc_mat) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(generate_data_key, keyring, enc_mat);
}

/**
 * The KR attempts to encrypt the data key. A data key should have already been generated in these
 * encryption materials by another KR.
 *
 * On success AWS_OP_SUCCESS is returned, one or more new EDKs will be appended onto the list of EDKs.
 *
 * On failure AWS_OP_ERR is returned, an internal AWS error code is set, and no memory is allocated.
 */
static inline int aws_cryptosdk_keyring_encrypt_data_key(
    struct aws_cryptosdk_keyring * keyring,
    struct aws_cryptosdk_encryption_materials * enc_mat) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(encrypt_data_key, keyring, enc_mat);
}

/**
 * The KR attempts to find one of the EDKs to decrypt. edks must be a list of struct aws_cryptosdk_edk
 * instances, not a list of pointers. Decryption materials should already have been initialized.
 *
 * On success AWS_OP_SUCCESS will be returned. This does not necessarily mean that the data key will be
 * decrypted, as it is normal behavior that a particular KR may not find an EDK that it can decrypt.
 * To determine whether the data key was decrypted, check dec_mat->unencrypted_data_key.buffer. If the
 * data key was not decrypted, that pointer will be set to NULL. If the data key was decrypted, that pointer
 * will point to the raw bytes of the key.
 *
 * On internal failure, AWS_OP_ERR will be returned and an internal error code will be set.
 */
static inline int aws_cryptosdk_keyring_decrypt_data_key(
    struct aws_cryptosdk_keyring * keyring,
    struct aws_cryptosdk_decryption_materials * dec_mat,
    const struct aws_cryptosdk_decryption_request * request) {
    AWS_CRYPTOSDK_PRIVATE_VF_CALL(decrypt_data_key, keyring, dec_mat, request);
}


/**
 * Allocates a new encryption materials object, including allocating memory to the list of EDKs. The list of
 * EDKs will be empty and no memory will be allocated to any byte buffers in that list, nor will memory be
 * allocated to the unencrypted data key buffer. They will only be allocated when individual keys are generated
 * or encrypted by other calls to the KR.
 *
 * On failure, returns NULL and an internal AWS error code is set.
 */
struct aws_cryptosdk_encryption_materials * aws_cryptosdk_encryption_materials_new(
    struct aws_allocator * alloc,
    enum aws_cryptosdk_alg_id alg);

/**
 * Deallocates all memory associated with the encryption materials object including the object itself.
 * All keys in the materials will have their associated memory also deallocated, but make sure that they have been
 * initialized properly per the comments on aws_cryptosdk_keyring_generate_data_key.
 */
void aws_cryptosdk_encryption_materials_destroy(struct aws_cryptosdk_encryption_materials * enc_mat);

/**
 * Allocates a new decryption materials object. Note that no memory will be allocated to the byte buffer for 
 * the unencrypted data key. That will only be allocated when an EDK is decrypted.
 *
 * TODO: Trailing signature key must be implemented, and if any preallocation of memory is needed add it here.
 *
 * On failure, returns NULL and an internal AWS error code is set.
 */
struct aws_cryptosdk_decryption_materials * aws_cryptosdk_decryption_materials_new(
    struct aws_allocator * alloc,
    enum aws_cryptosdk_alg_id alg);

/**
 * Deallocates all memory associated with the decryption materials object including the object itself and
 * the unencrypted data key it is holding, if an EDK has been decrypted successfully.
 */
void aws_cryptosdk_decryption_materials_destroy(struct aws_cryptosdk_decryption_materials * dec_mat);

#ifdef __cplusplus
}
#endif

#endif // AWS_CRYPTOSDK_MATERIALS_H
