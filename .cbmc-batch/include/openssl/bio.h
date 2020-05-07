/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_BIO_H
#define HEADER_BIO_H

#ifndef OPENSSL_NO_STDIO
#    include <stdio.h>
#endif
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <openssl/ossl_typ.h>

typedef int pem_password_cb(char *buf, int size, int rwflag, void *u);

BIO *BIO_new_mem_buf(const void *buf, signed int len);

EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

int BIO_free(BIO *a);

#ifdef __cplusplus
}
#endif
#endif
