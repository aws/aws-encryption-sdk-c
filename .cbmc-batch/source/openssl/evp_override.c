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

#include <make_common_data_structures.h>
#include <proof_helpers/nondet.h>

/* Abstraction of the EVP_PKEY struct */
struct evp_pkey_st {
  int references;
};

/* Helper function for CBMC proofs: initializes PKEY as nondeterministically as possible. */
void evp_pkey_nondet_init(EVP_PKEY* pkey) {
  int new_reference_count;
  __CPROVER_assume(new_reference_count > 0);
  pkey->references = new_reference_count;
}

/* Helper function for CBMC proofs: returns the reference count. */
int evp_pkey_get_reference_count(EVP_PKEY* pkey) {
  return pkey ? pkey->references : 0;
}

/* Helper function for CBMC proofs: frees the memory regardless of the reference count. */
void evp_pkey_unconditional_free(EVP_PKEY* pkey) {
  free(pkey);
}

/*
 * Description: The EVP_PKEY_new() function allocates an empty EVP_PKEY structure which is used by OpenSSL to store public and private keys. The reference count is set to 1.
 * Return values: EVP_PKEY_new() returns either the newly allocated EVP_PKEY structure or NULL if an error occurred.
 */
EVP_PKEY* EVP_PKEY_new() {
  EVP_PKEY* pkey = can_fail_malloc(sizeof(EVP_PKEY));

  if (pkey) {
    pkey->references = 1;
  }

  return pkey;
}

/*
 * Description: EVP_PKEY_free() decrements the reference count of key and, if the reference count is zero, frees it up. If key is NULL, nothing is done.
 */
void EVP_PKEY_free(EVP_PKEY *pkey) {
  if (pkey) {
    --pkey->references;
    if (pkey->references == 0) {
      free(pkey);
    }
  }
}

/* Abstraction of the EVP_MD_CTX struct */
struct evp_md_ctx_st {
    bool is_initialized;
    size_t data_count;
};

/* Abstraction of the EVP_MD struct */
struct evp_md_st {
    bool is_sha512;
};

bool evp_md_ctx_is_valid(EVP_MD_CTX *ctx) {
    return ctx && ctx->is_initialized && ctx->data_count <= EVP_MAX_MD_SIZE;
}

bool evp_md_ctx_is_initialized(EVP_MD_CTX *ctx) {
    return ctx->is_initialized;
}

size_t evp_md_ctx_data_count(EVP_MD_CTX *ctx) {
    return ctx->data_count;
}

void evp_md_ctx_nondet_init(EVP_MD_CTX *ctx) {
    ctx->is_initialized = true;
    size_t data_count;
    __CPROVER_assume(data_count <= EVP_MAX_MD_SIZE);
    ctx->data_count = data_count;
}

/*
 * Description: Allocates and returns a digest context.
 */
EVP_MD_CTX *EVP_MD_CTX_new() {
    EVP_MD_CTX *ctx = can_fail_malloc(sizeof(EVP_MD_CTX));

    // OpenSSL implementation uses OPENSSL_zalloc, which according to the documentation returns NULL on error.
    // Therefore, we cannot guarantee that pointer is not NULL.

    if (ctx) {
        ctx->is_initialized = false;
    }

    return ctx;
}

/*
 * Description: Cleans up digest context ctx and frees up the space allocated to it.
 */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    // OpenSSL implementation is a no-op if ctx is NULL
    if (ctx) {
        free(ctx);
    }
}

/*
 * Description: Sets up digest context ctx to use a digest type from ENGINE impl. type will typically be supplied by
 * a function such as EVP_sha1(). If impl is NULL then the default implementation of digest type is used. Return
 * values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
    assert(ctx != NULL);
    assert(!ctx->is_initialized);  // can a ctx be initialized twice?
    assert(type != NULL);
    assert(type->is_sha512);
    // impl can be NULL

    // Additional assumptions?

    ctx->is_initialized = nondet_bool();
    ctx->data_count     = 0;  // is this guaranteed?

    // Additional guarantees?

    return ctx->is_initialized;
}

/*
 * Description: Hashes cnt bytes of data at d into the digest context ctx. This function can be called several times
 * on the same ctx to hash additional data. Return values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
    assert(evp_md_ctx_is_valid(ctx));
    assert(d != NULL);  // is this a hard requirement?
    assert(AWS_MEM_IS_READABLE(d, cnt));
    assert(ctx->data_count + cnt <= EVP_MAX_MD_SIZE); // should we assume this? what happens otherwise?

    // Additional assumptions?

    if (nondet_bool()) {
        return 0;  // can failure invalidate ctx somehow?
    } else {
        ctx->data_count += cnt;
        return 1;
    }

    // Additional guarantees?
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
    assert(md != NULL);  // is this a hard requirement?
    assert(AWS_MEM_IS_WRITABLE(md, ctx->data_count));
    // s can be NULL

    // Additional assumptions?

    if (nondet_bool()) {
        if (s) {
            *s = ctx->data_count;
        }

        ctx->is_initialized = false;

        return 1;
    } else {
        // is ctx left initialized in case of failure?
        return 0;
    }

    // Additional guarantees?
}

/*
 * Description: The SHA-512 algorithm, which generates 512 bits of output from a given input.
 * Return values: These functions return a EVP_MD structure that contains the implementation of the symmetric
 * cipher.
 */
const EVP_MD *EVP_sha512() {
    static const EVP_MD md = { true };
    // OpenSSL implementation returns the address of a static struct
    return &md;
}
