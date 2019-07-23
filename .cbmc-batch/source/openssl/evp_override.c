/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <openssl/evp.h>

#include <ec_utils.h>
#include <make_common_data_structures.h>
#include <proof_helpers/nondet.h>

/* Abstraction of the EVP_PKEY struct */
struct evp_pkey_st {
    int references;
    EC_KEY *ec_key;
};

/*
 * Description: The EVP_PKEY_new() function allocates an empty EVP_PKEY structure which is used by OpenSSL to store
 * public and private keys. The reference count is set to 1. Return values: EVP_PKEY_new() returns either the newly
 * allocated EVP_PKEY structure or NULL if an error occurred.
 */
EVP_PKEY *EVP_PKEY_new() {
    EVP_PKEY *pkey = can_fail_malloc(sizeof(EVP_PKEY));

    if (pkey) {
        pkey->references = 1;
        pkey->ec_key     = NULL;
    }

    return pkey;
}

/*
 * Description: EVP_PKEY_get0_EC_KEY() also returns the referenced key in pkey or NULL if the key is not of the correct
 * type but the reference count of the returned key is not incremented and so must not be freed up after use. Return
 * value: EVP_PKEY_get0_EC_KEY() returns the referenced key or NULL if an error occurred.
 */
EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey) {
    assert(pkey);

    // In our current model, the key is always of type EC
    return pkey->ec_key;
}

/*
 * Description: EVP_PKEY_set1_EC_KEY() sets the key referenced by pkey to key.
 * Return values: EVP_PKEY_set1_EC_KEY() returns 1 for success or 0 for failure.
 */
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key) {
    if (pkey == NULL || key == NULL || nondet_bool()) {
        return 0;
    }

    EC_KEY_up_ref(key);
    pkey->ec_key = key;

    return 1;
}

/*
 * Description: EVP_PKEY_free() decrements the reference count of key and, if the reference count is zero, frees it up.
 * If key is NULL, nothing is done.
 */
void EVP_PKEY_free(EVP_PKEY *pkey) {
    if (pkey) {
        pkey->references -= 1;
        if (pkey->references == 0) {
            EC_KEY_free(pkey->ec_key);
            free(pkey);
        }
    }
}

enum evp_aes { EVP_AES_128_GCM, EVP_AES_192_GCM, EVP_AES_256_GCM };

/* Abstraction of the EVP_CIPHER struct */
struct evp_cipher_st {
    enum evp_aes from;
};

/*
 * Description: AES for 128, 192 and 256 bit keys in Galois Counter Mode (GCM). These ciphers require additional control
 * operations to function correctly, see the "AEAD Interface" in EVP_EncryptInit(3) section for details. Return values:
 * These functions return an EVP_CIPHER structure that contains the implementation of the symmetric cipher.
 */
const EVP_CIPHER *EVP_aes_128_gcm(void) {
    static const EVP_CIPHER cipher = { EVP_AES_128_GCM };
    return &cipher;
}
const EVP_CIPHER *EVP_aes_192_gcm(void) {
    static const EVP_CIPHER cipher = { EVP_AES_192_GCM };
    return &cipher;
}
const EVP_CIPHER *EVP_aes_256_gcm(void) {
    static const EVP_CIPHER cipher = { EVP_AES_256_GCM };
    return &cipher;
}

enum evp_sha { EVP_SHA256, EVP_SHA384, EVP_SHA512 };

/* Abstraction of the EVP_MD struct */
struct evp_md_st {
    enum evp_sha from;
    size_t size;
};

/*
 * Description: The SHA-2 SHA-224, SHA-256, SHA-512/224, SHA512/256, SHA-384 and SHA-512 algorithms, which generate 224,
 * 256, 224, 256, 384 and 512 bits respectively of output from a given input. Return values: These functions return a
 * EVP_MD structure that contains the implementation of the symmetric cipher.
 */
const EVP_MD *EVP_sha256() {
    static const EVP_MD md = { EVP_SHA256, 32 };
    return &md;
}
const EVP_MD *EVP_sha384() {
    static const EVP_MD md = { EVP_SHA384, 48 };
    return &md;
}
const EVP_MD *EVP_sha512() {
    static const EVP_MD md = { EVP_SHA512, 64 };
    return &md;
}

/* Abstraction of the EVP_MD_CTX struct */
struct evp_md_ctx_st {
    bool is_initialized;
    EVP_PKEY *pkey;
    size_t digest_size;
};

/*
 * Description: Allocates and returns a digest context.
 */
EVP_MD_CTX *EVP_MD_CTX_new() {
    EVP_MD_CTX *ctx = can_fail_malloc(sizeof(EVP_MD_CTX));

    if (ctx) {
        ctx->is_initialized = false;
        ctx->pkey           = NULL;
        ctx->digest_size    = 0;
    }

    return ctx;
}

/*
 * Description: Cleans up digest context ctx and frees up the space allocated to it.
 */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    if (ctx) {
        EVP_PKEY_free(ctx->pkey);
        free(ctx);
    }
}

/*
 * Description: Sets up digest context ctx to use a digest type from ENGINE impl. type will typically be supplied by
 * a function such as EVP_sha1(). If impl is NULL then the default implementation of digest type is used. Return
 * values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
    assert(ctx);
    assert(!ctx->is_initialized);
    assert(evp_md_is_valid(type));
    assert(!impl);  // Assuming that this function is always called in ESDK with impl == NULL

    if (nondet_bool()) return 0;

    ctx->is_initialized = true;
    ctx->digest_size    = type->size;

    return ctx->is_initialized;
}

/*
 * Description: Hashes cnt bytes of data at d into the digest context ctx. This function can be called several times
 * on the same ctx to hash additional data. Return values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
    assert(evp_md_ctx_is_valid(ctx));
    assert(d);
    assert(AWS_MEM_IS_READABLE(d, cnt));

    if (nondet_bool()) {
        ctx->is_initialized = false;
        return 0;
    }

    return 1;
}

/*
 * Description: Retrieves the digest value from ctx and places it in md. If the s parameter is not NULL then the
 * number of bytes of data written (i.e. the length of the digest) will be written to the integer at s, at most
 * EVP_MAX_MD_SIZE bytes will be written. After calling EVP_DigestFinal_ex() no additional calls to
 * EVP_DigestUpdate() can be made, but EVP_DigestInit_ex() can be called to initialize a new digest operation.
 * Return values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) {
    assert(evp_md_ctx_is_valid(ctx));
    assert(md);
    assert(AWS_MEM_IS_WRITABLE(md, ctx->digest_size));
    assert(s);  // Assuming that this function is always called in ESDK with s != NULL

    if (nondet_bool()) {
        ctx->is_initialized = false;
        return 0;
    }

    unsigned char start;               // arbitrary first byte
    __CPROVER_array_copy(md, &start);  // copies the first byte from start and assigns the rest arbitrarily
    *s                  = ctx->digest_size;
    ctx->is_initialized = false;
    return 1;
}

/*
 * Description: EVP_DigestVerifyInit() sets up verification context ctx to use digest type from ENGINE e and public key
 * pkey. ctx must be created with EVP_MD_CTX_new() before calling this function. If pctx is not NULL, the EVP_PKEY_CTX
 * of the verification operation will be written to *pctx: this can be used to set alternative verification options.
 * Note that any existing value in *pctx is overwritten. The EVP_PKEY_CTX value returned must not be freed directly by
 * the application if ctx is not assigned an EVP_PKEY_CTX value before being passed to EVP_DigestVerifyInit() (which
 * means the EVP_PKEY_CTX is created inside EVP_DigestVerifyInit() and it will be freed automatically when the
 * EVP_MD_CTX is freed).
 * Return values: EVP_DigestVerifyInit() EVP_DigestVerifyUpdate() return 1 for success and 0 for
 * failure.
 */
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) {
    assert(ctx);
    assert(!ctx->is_initialized);
    assert(!pctx);  // Assuming that this function is always called in ESDK with pctx == NULL
    assert(evp_md_is_valid(type));
    assert(!e);  // Assuming that this function is always called in ESDK with e == NULL
    assert(evp_pkey_is_valid(pkey));

    if (nondet_bool()) return 0;

    ctx->is_initialized = true;
    ctx->pkey           = pkey;
    pkey->references += 1;
    ctx->digest_size = type->size;

    return 1;
}

/*
 * Description: EVP_DigestVerifyFinal() verifies the data in ctx against the signature in sig of length siglen.
 * Return values: EVP_DigestVerifyFinal() and EVP_DigestVerify() return 1 for success; any other value indicates
 * failure. A return value of zero indicates that the signature did not verify successfully (that is, tbs did not match
 * the original data or the signature had an invalid form), while other values indicate a more serious error (and
 * sometimes also indicate an invalid signature form).
 */
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen) {
    assert(evp_md_ctx_is_valid(ctx));
    assert(sig);
    assert(AWS_MEM_IS_READABLE(sig, siglen));

    return nondet_int();
}

/* CBMC helper functions */

/* Helper function for CBMC proofs: checks if EVP_PKEY is valid. */
bool evp_pkey_is_valid(EVP_PKEY *pkey) {
    return pkey && (pkey->references > 0) && ec_key_is_valid(pkey->ec_key);
}

/* Helper function for CBMC proofs: allocates EVP_PKEY nondeterministically. */
EVP_PKEY *evp_pkey_nondet_alloc() {
    EVP_PKEY *pkey = can_fail_malloc(sizeof(EVP_PKEY));
    return pkey;
}

/* Helper function for CBMC proofs: returns the reference count. */
int evp_pkey_get_reference_count(EVP_PKEY *pkey) {
    return pkey ? pkey->references : 0;
}

/* Helper function for CBMC proofs: set EC_KEY without incrementing the reference count. */
void evp_pkey_set0_ec_key(EVP_PKEY *pkey, EC_KEY *ec) {
    if (pkey) pkey->ec_key = ec;
}

/* Helper function for CBMC proofs: frees the memory regardless of the reference count. */
void evp_pkey_unconditional_free(EVP_PKEY *pkey) {
    free(pkey);
    // Does not free EC_KEY, since this is always done separately in our use cases
}

bool evp_cipher_is_valid(EVP_CIPHER *cipher) {
    return cipher &&
           (cipher->from == EVP_AES_128_GCM || cipher->from == EVP_AES_192_GCM || cipher->from == EVP_AES_256_GCM);
}

bool evp_md_is_valid(EVP_MD *md) {
    return md && ((md->from == EVP_SHA256 && md->size == 32) || (md->from == EVP_SHA384 && md->size == 48) ||
                  (md->from == EVP_SHA512 && md->size == 64));
}

/* Helper function for CBMC proofs: checks if EVP_MD_CTX is valid. */
bool evp_md_ctx_is_valid(EVP_MD_CTX *ctx) {
    return ctx && ctx->is_initialized && ctx->digest_size <= EVP_MAX_MD_SIZE &&
           (ctx->pkey == NULL || evp_pkey_is_valid(ctx->pkey));
}

/* Helper function for CBMC proofs: allocates EVP_PKEY nondeterministically. */
EVP_MD_CTX *evp_md_ctx_nondet_alloc() {
    return can_fail_malloc(sizeof(EVP_MD_CTX));
}

/* Helper function for CBMC proofs: checks if EVP_MD_CTX is initialized. */
bool evp_md_ctx_is_initialized(EVP_MD_CTX *ctx) {
    return ctx->is_initialized;
}

/* Helper function for CBMC proofs: returns digest size. */
size_t evp_md_ctx_get_digest_size(EVP_MD_CTX *ctx) {
    return ctx->digest_size;
}

/* Helper function for CBMC proofs: get EVP_PKEY without incrementing the reference count. */
EVP_PKEY *evp_md_ctx_get0_evp_pkey(EVP_MD_CTX *ctx) {
    return ctx ? ctx->pkey : NULL;
}

/* Helper function for CBMC proofs: set EVP_PKEY without incrementing the reference count. */
void evp_md_ctx_set0_evp_pkey(EVP_MD_CTX *ctx, EVP_PKEY *pkey) {
    if (ctx) ctx->pkey = pkey;
}

/* Helper function for CBMC proofs: frees the memory of the ctx without freeing the EVP_PKEY. */
void evp_md_ctx_shallow_free(EVP_MD_CTX *ctx) {
    free(ctx);
    // Does not free EVP_KEY, since this is always done separately in our use cases
}
