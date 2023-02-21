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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <proof_helpers/proof_allocators.h>

/* Abstraction of the BIO struct */

struct bio_st {
    size_t key_len;
};

/*
 * Decription: BIO_new_mem_buf() creates a memory BIO using len bytes of data at buf, if len is -1 then the buf is
 * assumed to be null terminated and its length is determined by strlen. The BIO is set to a read only state and as a
 * result cannot be written to. This is useful when some data needs to be made available from a static area of memory in
 * the form of a BIO. The supplied data is read directly from the supplied buffer: it is not copied first, so the
 * supplied area of memory must be unchanged until the BIO is freed.
 */
BIO *BIO_new_mem_buf(const void *buf, signed int len) {
    BIO *bio = can_fail_malloc(sizeof(BIO));
    if (bio) {
        bio->key_len = len;
    }
    return bio;
}

/*
 * The PUBKEY functions process a public key using an EVP_PKEY structure. The public key is encoded as a
 * SubjectPublicKeyInfo structure.
 */
EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
    *x = EVP_PKEY_new();
    return *x;
}

/*
 * Read a private key from a BIO.
 */
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
    *x = EVP_PKEY_new();
    return *x;
}

/*
 * BIO_free() frees up a single BIO, BIO_vfree() also frees up a single BIO but it does not return a value.
 * If a is NULL nothing is done. Calling BIO_free() may also have some effect on the underlying I/O structure,
 * for example it may close the file being referred to under certain circumstances. For more details see the individual
 * BIO_METHOD descriptions.
 */
int BIO_free(BIO *a) {
    if (a != NULL) {
        free(a);
    }
}
