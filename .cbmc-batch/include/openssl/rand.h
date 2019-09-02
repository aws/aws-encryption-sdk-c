/*
 * Changes to OpenSSL version 1.1.1. copyright 2019 Amazon.com, Inc. All Rights Reserved.
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
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


#ifndef HEADER_RAND_H
# define HEADER_RAND_H

# include <stdlib.h>
# include <openssl/ossl_typ.h>


#ifdef  __cplusplus
extern "C" {
#endif

int RAND_bytes(unsigned char *buf, int num);


#ifdef  __cplusplus
}
#endif

#endif

