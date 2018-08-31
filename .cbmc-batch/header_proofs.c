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

#include <aws/common/byte_buf.h>
#include <stdlib.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/header.h>
#include "proof_helpers.h"
#define MAX_AAD_COUNT 1
#define MAX_EDK_COUNT 1
#define MAX_BUFFER_LEN 1

struct aws_cryptosdk_hdr * get_aws_cryptosdk_hdr_ptr(struct aws_allocator * allocator, bool full_init) {
    struct aws_cryptosdk_hdr * hdr;
    // Assume hdr is allocated
    ASSUME_VALID_MEMORY(hdr);
    hdr->aad_tbl = NULL;
    // Assume that hdr->aad_count is below some bound
    __CPROVER_assume(hdr->aad_count <= MAX_AAD_COUNT);
    if (hdr->aad_count > 0) {
        // Assume that hdr->aad_tbl is allocated memory for hdr->aad_count entries
        hdr->aad_tbl = aws_mem_acquire(allocator, hdr->aad_count * sizeof(*(hdr->aad_tbl)));
        for (int i = 0; i < hdr->aad_count; i++) {
            // For each entry in hdr->aad_tbl
            struct aws_cryptosdk_hdr_aad * aad = hdr->aad_tbl + i;
            size_t key_len = nondet_size_t();
            size_t value_len = nondet_size_t();
            // Assume key_len is below bound on buffer length
            __CPROVER_assume(key_len < MAX_BUFFER_LEN);
            // Assume value_len is below bound on buffer length
            __CPROVER_assume(value_len < MAX_BUFFER_LEN);
            // Nondeterministically initialize buffers or make sure that either
            // the allocators or buffers are NULL
            if (full_init)
                aws_byte_buf_init(allocator, &aad->key, key_len);
            else if (nondet_int())
                aad->key.allocator = NULL;
            else
                aad->key.buffer = NULL;
            if (full_init)
                aws_byte_buf_init(allocator, &aad->value, value_len);
            else if (nondet_int())
                aad->value.allocator = NULL;
            else
                aad->value.buffer = NULL;
        }
    }
    hdr->edk_tbl = NULL;
    // Assume that hdr->edk_count is below some bound
    __CPROVER_assume(hdr->edk_count <= MAX_EDK_COUNT);
    if (hdr->edk_count > 0) {
        // Assume that hdr->edk_tbl is allocated memory for hdr->edk_count entries
        hdr->edk_tbl = aws_mem_acquire(allocator, hdr->edk_count * sizeof(*(hdr->edk_tbl)));
        for (int i = 0; i < hdr->edk_count; i++) {
            // For each entry in hdr->edk_tbl
            struct aws_cryptosdk_edk * edk = hdr->edk_tbl + i;
            size_t provider_id_len = nondet_size_t();
            size_t provider_info_len = nondet_size_t();
            size_t enc_data_key_len = nondet_size_t();
            // Assume provider_id_len is below bound on buffer length
            __CPROVER_assume(provider_id_len < MAX_BUFFER_LEN);
            // Assume provider_info_len is below bound on buffer length
            __CPROVER_assume(provider_info_len < MAX_BUFFER_LEN);
            // Assume enc_data_key_len is below bound on buffer length
            __CPROVER_assume(enc_data_key_len < MAX_BUFFER_LEN);
            // Nondeterministically initialize buffers or make sure that either
            // the allocators or buffers are NULL
            if (full_init)
                aws_byte_buf_init(allocator, &edk->provider_id, provider_id_len);
            else if (nondet_int())
                edk->provider_id.allocator = NULL;
            else
                edk->provider_id.buffer = NULL;
            if (full_init)
                aws_byte_buf_init(allocator, &edk->provider_info, provider_info_len);
            else if (nondet_int())
                edk->provider_info.allocator = NULL;
            else
                edk->provider_info.buffer = NULL;
            if (full_init)
                aws_byte_buf_init(allocator, &edk->enc_data_key, enc_data_key_len);
            else if (nondet_int())
                edk->enc_data_key.allocator = NULL;
            else
                edk->enc_data_key.buffer = NULL;
        }
    }

    size_t iv_len = nondet_size_t();
    // Assume that iv_len is below some bound
    __CPROVER_assume(iv_len < MAX_BUFFER_LEN);
    // Assume that &hdr->iv is appropriately initialized
    aws_byte_buf_init(allocator, &hdr->iv, iv_len);

    size_t auth_tag_len = nondet_size_t();
    // Assume that auth_tag_len is below some bound
    __CPROVER_assume(auth_tag_len < MAX_BUFFER_LEN);
    // Assume that &hdr->auth_tag is appropriately initialized
    aws_byte_buf_init(allocator, &hdr->auth_tag, iv_len);

    return hdr;
}

void aws_cryptosdk_hdr_clean_up_verify(void) {
    struct aws_allocator * allocator;
    // Use default allocator
    ASSUME_DEFAULT_ALLOCATOR(allocator);
    struct aws_cryptosdk_hdr * hdr = get_aws_cryptosdk_hdr_ptr(allocator, nondet_int());
    aws_cryptosdk_hdr_clean_up(allocator, hdr);
    free(hdr);
}

void aws_cryptosdk_hdr_write_verify(void) {
    struct aws_allocator * allocator;
    // Use default allocator
    ASSUME_DEFAULT_ALLOCATOR(allocator);
    struct aws_cryptosdk_hdr * hdr = get_aws_cryptosdk_hdr_ptr(allocator, true);

    size_t * bytes_written;
    ASSUME_VALID_MEMORY(bytes_written);
    size_t outlen = nondet_size_t();
    __CPROVER_assume(outlen < __CPROVER_constant_infinity_uint - 1);
    uint8_t * outbuf;
    ASSUME_VALID_MEMORY_COUNT(outbuf, outlen);

    aws_cryptosdk_hdr_write(hdr, bytes_written, outbuf, outlen);
}

void aws_cryptosdk_hdr_size_verify(void) {
    struct aws_allocator * allocator;
    // Use default allocator
    ASSUME_DEFAULT_ALLOCATOR(allocator);
    struct aws_cryptosdk_hdr * hdr = get_aws_cryptosdk_hdr_ptr(allocator, true);

    aws_cryptosdk_hdr_size(hdr); 
}
