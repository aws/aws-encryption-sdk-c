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

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#    define _BSD_SOURCE
#    include <sys/mman.h>
#    include <unistd.h>
#endif

#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/cryptosdk/edk.h>
#include <aws/cryptosdk/enc_ctx.h>
#include <aws/cryptosdk/private/header.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "testutil.h"

#ifdef _MSC_VER
#    include <malloc.h>
#    define alloca _alloca
#endif

struct aws_cryptosdk_hdr_aad {
    struct aws_byte_buf key, value;
};

// clang-format off
static const uint8_t test_header_1[] = {
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14,
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,
    //AAD length (19 bytes)
    0x00, 0x13,
    //AAD - kv pair count (2 pairs)
    0x00, 0x02,
    //key length, key data
    0x00,  0x00,
    //val length, val data
    0x00,  0x00,
    //key length, key data
    0x00,  0x04,
    0x01,  0x02,  0x03,  0x04,
    //value length, value data
    0x00,  0x05,
    0x01,  0x00,  0x01,  0x00,  0x01,
// p = 49 bytes
    //edk count
    0x00, 0x03,
    //edk #0 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00,
    //edk #1
    //provider ID len + data
    0x00,  0x04,  0x10,  0x11,  0x12,  0x00,
    //prov info len + data
    0x00,  0x04,  0x01,  0x02,  0x03,  0x04,
    //encrypted data key
    0x00,  0x08,  0x11,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x88,
    //edk #2 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00,

    //content type
    0x02,

    //reserved
    0x00,  0x00,  0x00,  0x00,
    //iv len
    0x0c,
    //frame length
    0x00,  0x00,  0x10,  0x00,
    //iv  FIXME: this IV and authentication tag is not valid, change when we implement authentication
    0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,
    //header auth
    0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef,
    // extra byte - used to verify that we can parse with extra trailing junk
    0xFF
};
static const uint8_t test_headerV2_1[] = {
    // version
    0x02,
    // alg ID
    0x04, 0x78,
    // message ID
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    // AAD length (24 bytes)
    0x00, 0x18,
    // AAD - key value pair count (2 pairs)
    0x00, 0x02,
    // AAD - key value pair entry 0
    0x00, 0x04,              // key length
    0x54, 0x65, 0x73, 0x74,  // key
    0x00, 0x03,              // value length
    0x4f, 0x6e, 0x65,        // value
    // AAD - key value pair entry 1
    0x00, 0x04,              // key length
    0x54, 0x73, 0x73, 0x74,  // key
    0x00, 0x03,              // value length
    0x54, 0x77, 0x6f,        // value
    // EDK count (1 EDK)
    0x00, 0x01,
    // EDK 0
    0x00, 0x04,              // key provider ID length
    0x50, 0x72, 0x6f, 0x76,  // key provider ID
    0x00, 0x04,              // key provider info length
    0x49, 0x6e, 0x66, 0x6f,  // key provider info
    0x00, 0x10,              // EDK length
    0x59, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x53,  // ciphertext
    0x75, 0x62, 0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65,  // ciphertext, cont.
    // content type
    0x02,
    // frame length
    0x00, 0x00, 0x10, 0x00,
    // algorithm suite data (commitment)
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    // header auth tag
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    // extra byte to verify we can parse with trailing junk
    0xff
};
// clang-format on

uint8_t test_header_1_aad_key[]                      = { 0x01, 0x02, 0x03, 0x04 };
uint8_t test_header_1_aad_value[]                    = { 0x01, 0x00, 0x01, 0x00, 0x01 };
struct aws_cryptosdk_hdr_aad test_header_1_aad_tbl[] = {
    { .key   = { .len = sizeof(test_header_1_aad_key), .buffer = test_header_1_aad_key },
      .value = { .len = sizeof(test_header_1_aad_value), .buffer = test_header_1_aad_value } },
    { { 0 } }
};

uint8_t test_header_1_edk_provider_id[]          = { 0x10, 0x11, 0x12, 0x00 };
uint8_t test_header_1_edk_provider_info[]        = { 0x01, 0x02, 0x03, 0x04 };
uint8_t test_header_1_edk_enc_data_key[]         = { 0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88 };
struct aws_cryptosdk_edk test_header_1_edk_tbl[] = {
    { { 0 } },
    { .provider_id   = { .len      = sizeof(test_header_1_edk_provider_id),
                       .buffer   = test_header_1_edk_provider_id,
                       .capacity = sizeof(test_header_1_edk_provider_id) },
      .provider_info = { .len      = sizeof(test_header_1_edk_provider_info),
                         .buffer   = test_header_1_edk_provider_info,
                         .capacity = sizeof(test_header_1_edk_provider_info) },
      .ciphertext    = { .len      = sizeof(test_header_1_edk_enc_data_key),
                      .buffer   = test_header_1_edk_enc_data_key,
                      .capacity = sizeof(test_header_1_edk_enc_data_key) } },
    { { 0 } }
};

uint8_t test_header_1_iv_arr[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };

uint8_t test_header_1_auth_tag_arr[] = { 0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef };

uint8_t test_header_1_message_id_arr[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
uint8_t test_header_2_message_id_arr[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

uint8_t test_headerV2_1_message_id_arr[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
uint8_t test_headerV2_1_aad_key0[]                     = { 0x54, 0x65, 0x73, 0x74 };
uint8_t test_headerV2_1_aad_key1[]                     = { 0x54, 0x73, 0x73, 0x74 };
uint8_t test_headerV2_1_aad_value0[]                   = { 0x4f, 0x6e, 0x65 };
uint8_t test_headerV2_1_aad_value1[]                   = { 0x54, 0x77, 0x6f };
struct aws_cryptosdk_hdr_aad test_headerV2_1_aad_tbl[] = {
    { .key   = { .len = sizeof(test_headerV2_1_aad_key0), .buffer = test_headerV2_1_aad_key0 },
      .value = { .len = sizeof(test_headerV2_1_aad_value0), .buffer = test_headerV2_1_aad_value0 } },
    { .key   = { .len = sizeof(test_headerV2_1_aad_key1), .buffer = test_headerV2_1_aad_key1 },
      .value = { .len = sizeof(test_headerV2_1_aad_value1), .buffer = test_headerV2_1_aad_value1 } }
};
uint8_t test_headerV2_1_edk_provider_id[]   = { 0x50, 0x72, 0x6f, 0x76 };
uint8_t test_headerV2_1_edk_provider_info[] = { 0x49, 0x6e, 0x66, 0x6f };
uint8_t test_headerV2_1_edk_enc_data_key[]  = {
    0x59, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x53, 0x75, 0x62, 0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65,
};
struct aws_cryptosdk_edk test_headerV2_1_edk_tbl[] = {
    { .provider_id   = { .len      = sizeof(test_headerV2_1_edk_provider_id),
                       .buffer   = test_headerV2_1_edk_provider_id,
                       .capacity = sizeof(test_headerV2_1_edk_provider_id) },
      .provider_info = { .len      = sizeof(test_headerV2_1_edk_provider_info),
                         .buffer   = test_headerV2_1_edk_provider_info,
                         .capacity = sizeof(test_headerV2_1_edk_provider_info) },
      .ciphertext    = { .len      = sizeof(test_headerV2_1_edk_enc_data_key),
                      .buffer   = test_headerV2_1_edk_enc_data_key,
                      .capacity = sizeof(test_headerV2_1_edk_enc_data_key) } }
};
uint8_t test_headerV2_1_alg_suite_data_arr[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
uint8_t test_headerV2_1_auth_tag_arr[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

#define SET_EDK_TBL(hdr, edks)                                        \
    do {                                                              \
        set_edk_tbl((hdr), (edks), sizeof(edks) / sizeof((edks)[0])); \
    } while (0)

#define SET_AAD_TBL(hdr, aads)                             \
    do {                                                   \
        size_t aad_count = sizeof(aads) / sizeof(aads[0]); \
        set_aad_tbl((hdr), aads, aad_count);               \
    } while (0)

void set_edk_tbl(struct aws_cryptosdk_hdr *hdr, struct aws_cryptosdk_edk *edks, size_t count) {
    if (aws_cryptosdk_edk_list_init(aws_default_allocator(), &hdr->edk_list)) abort();

    for (size_t i = 0; i < count; i++) {
        aws_array_list_push_back(&hdr->edk_list, &edks[i]);
    }
}

void set_aad_tbl(struct aws_cryptosdk_hdr *hdr, struct aws_cryptosdk_hdr_aad *aads, size_t count) {
    if (aws_cryptosdk_enc_ctx_init(aws_default_allocator(), &hdr->enc_ctx)) {
        abort();
    }

    for (size_t i = 0; i < count; i++) {
        const struct aws_string *k, *v;
        k = aws_string_new_from_array(aws_default_allocator(), aads[i].key.buffer, aads[i].key.len);
        v = aws_string_new_from_array(aws_default_allocator(), aads[i].value.buffer, aads[i].value.len);

        if (!k || !v || aws_hash_table_put(&hdr->enc_ctx, k, (void *)v, NULL)) {
            abort();
        }
    }
}

static struct aws_cryptosdk_hdr test_header_1_hdr() {
    struct aws_allocator *allocator = aws_default_allocator();

    struct aws_cryptosdk_hdr test_header_1_hdr = {
        .alg_id     = ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        .frame_len  = 0x1000,
        .iv         = { .buffer = test_header_1_iv_arr, .len = sizeof(test_header_1_iv_arr) },
        .auth_tag   = { .buffer = test_header_1_auth_tag_arr, .len = sizeof(test_header_1_auth_tag_arr) },
        .message_id = { .buffer = test_header_1_message_id_arr, .len = sizeof(test_header_1_message_id_arr) },
        .alg_suite_data = { .buffer = NULL, .len = 0 },
        //        .aad_tbl = test_header_1_aad_tbl,
        //        .edk_tbl = test_header_1_edk_tbl,
        .auth_len = sizeof(test_header_1) - 29  // not used by aws_cryptosdk_hdr_size/write
    };
    test_header_1_hdr.iv = aws_byte_buf_from_array(test_header_1_iv_arr, sizeof(test_header_1_iv_arr));
    test_header_1_hdr.auth_tag =
        aws_byte_buf_from_array(test_header_1_auth_tag_arr, sizeof(test_header_1_auth_tag_arr));
    test_header_1_hdr.alloc = allocator;

    SET_EDK_TBL(&test_header_1_hdr, test_header_1_edk_tbl);
    SET_AAD_TBL(&test_header_1_hdr, test_header_1_aad_tbl);

    return test_header_1_hdr;
}

static struct aws_cryptosdk_hdr test_headerV2_1_hdr() {
    struct aws_cryptosdk_hdr hdr = {
        .alloc          = aws_default_allocator(),
        .alg_id         = ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY,
        .frame_len      = 0x1000,
        .iv             = { .buffer = NULL, .len = 0 },
        .auth_tag       = { .buffer = test_headerV2_1_auth_tag_arr, .len = sizeof(test_headerV2_1_auth_tag_arr) },
        .message_id     = { .buffer = test_headerV2_1_message_id_arr, .len = sizeof(test_headerV2_1_message_id_arr) },
        .alg_suite_data = { .buffer = test_headerV2_1_alg_suite_data_arr,
                            .len    = sizeof(test_headerV2_1_alg_suite_data_arr) },
        .auth_len       = sizeof(test_headerV2_1) - 1 - 16  // not used by aws_cryptosdk_hdr_size/write
    };
    SET_EDK_TBL(&hdr, test_headerV2_1_edk_tbl);
    SET_AAD_TBL(&hdr, test_headerV2_1_aad_tbl);
    return hdr;
}

// clang-format off
static const uint8_t test_header_2[] = { // same as test_header_1 with no AAD section
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14,
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,
    //AAD length (0 bytes)
    0x00, 0x00,
    //edk count
    0x00, 0x03,
    //edk #0 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00,
    //edk #1
    //provider ID len + data
    0x00,  0x04,  0x10,  0x11,  0x12,  0x00,
    //prov info len + data
    0x00,  0x04,  0x01,  0x02,  0x03,  0x04,
    //encrypted data key
    0x00,  0x08,  0x11,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x88,
    //edk #2 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00,

    //content type
    0x02,

    //reserved
    0x00,  0x00,  0x00,  0x00,
    //iv len
    0x0c,
    //frame length
    0x00,  0x00,  0x10,  0x00,
    //iv  FIXME: this IV and authentication tag is not valid, change when we implement authentication
    0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,
    //header auth
    0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef,
    // extra byte - used to verify that we can parse with extra trailing junk
    0xFF
};

static const uint8_t hdr_with_nonzero_reserve_bytes[] = {
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14,
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,
    //AAD length (0 bytes)
    0x00, 0x00,
    //edk count
    0x00, 0x01,
    //edk #0 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00,
    //content type
    0x02,
    //reserved
    0x00,  0x00,  0x00,  0x01,
    //iv len
    0x0c,
    //frame length
    0x00,  0x00,  0x10,  0x00,
    //iv  FIXME: this IV and authentication tag is not valid, change when we implement authentication
    0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,
    //header auth
    0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef
};

static const uint8_t hdr_with_zero_aad_count[] = { // AAD len can be zero, but AAD count cannot
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14,
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,
    //AAD length (2 bytes)
    0x00, 0x02,
    //AAD count
    0x00, 0x00,
    //edk count
    0x00, 0x01,
    //edk #0 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00,
    //content type
    0x02,
    //reserved
    0x00,  0x00,  0x00,  0x00,
    //iv len
    0x0c,
    //frame length
    0x00,  0x00,  0x10,  0x00,
    //iv  FIXME: this IV and authentication tag is not valid, change when we implement authentication
    0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,
    //header auth
    0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef
};

static const uint8_t hdr_with_zero_edk_count[] = {
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14,
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,
    //AAD length (0 bytes)
    0x00, 0x00,
    //edk count
    0x00, 0x00,
    //content type
    0x02,
    //reserved
    0x00,  0x00,  0x00,  0x00,
    //iv len
    0x0c,
    //frame length
    0x00,  0x00,  0x10,  0x00,
    //iv  FIXME: this IV and authentication tag is not valid, change when we implement authentication
    0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,
    //header auth
    0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef
};
// clang-format on

static const uint8_t *bad_headers[]  = { hdr_with_nonzero_reserve_bytes,
                                        hdr_with_zero_aad_count,
                                        hdr_with_zero_edk_count };
static const size_t bad_headers_sz[] = { sizeof(hdr_with_nonzero_reserve_bytes),
                                         sizeof(hdr_with_zero_aad_count),
                                         sizeof(hdr_with_zero_edk_count) };

struct aws_cryptosdk_hdr test_header_2_hdr() {
    // clang-format off
    struct aws_cryptosdk_hdr hdr = {
        .alg_id = ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
        .frame_len = 0x1000,
        .iv = {.buffer = test_header_1_iv_arr, .len = sizeof(test_header_1_iv_arr)},
        .auth_tag = {.buffer = test_header_1_auth_tag_arr, .len = sizeof(test_header_1_auth_tag_arr)},
        .message_id = {.buffer = test_header_2_message_id_arr, .len = sizeof(test_header_2_message_id_arr)},
        .auth_len = sizeof(test_header_2) - 29 // not used by aws_cryptosdk_hdr_size/write
    };
    // clang-format on

    hdr.alloc = aws_default_allocator();

    set_aad_tbl(&hdr, NULL, 0);
    SET_EDK_TBL(&hdr, test_header_1_edk_tbl);

    return hdr;
}

int simple_header_parse() {
    struct aws_cryptosdk_hdr hdr;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(test_header_1, sizeof(test_header_1) - 1);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_hdr_init(&hdr, aws_default_allocator()));
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_parse(&hdr, &cursor));
    TEST_ASSERT_INT_EQ(cursor.len, 0);
    TEST_ASSERT_ADDR_EQ(cursor.ptr, test_header_1 + sizeof(test_header_1) - 1);

    // Known answer tests
    TEST_ASSERT_INT_EQ(hdr.alg_id, ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256);

    struct aws_byte_cursor message_id = aws_byte_cursor_from_buf(&hdr.message_id);
    TEST_ASSERT_CUR_EQ(
        message_id, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);

    TEST_ASSERT_BUF_EQ(hdr.iv, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b);

    TEST_ASSERT_BUF_EQ(
        hdr.auth_tag, 0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef);

    // Misc values
    TEST_ASSERT_INT_EQ(2, aws_hash_table_get_entry_count(&hdr.enc_ctx));
    TEST_ASSERT_INT_EQ(3, aws_array_list_length(&hdr.edk_list));
    TEST_ASSERT_INT_EQ(0x1000, hdr.frame_len);
    TEST_ASSERT_INT_EQ(hdr.auth_len, sizeof(test_header_1) - 29);  // 1 junk byte, 12 IV bytes, 16 auth tag bytes

    // AAD checks
    AWS_STATIC_STRING_FROM_LITERAL(k1, "\x01\x02\x03\x04");
    AWS_STATIC_STRING_FROM_LITERAL(v1, "\x01\x00\x01\x00\x01");

    struct aws_hash_element *pElem;
    TEST_ASSERT_SUCCESS(aws_hash_table_find(&hdr.enc_ctx, k1, &pElem));
    TEST_ASSERT_ADDR_NOT_NULL(pElem);
    TEST_ASSERT(aws_string_eq(pElem->value, v1));

    AWS_STATIC_STRING_FROM_LITERAL(empty, "");

    TEST_ASSERT_SUCCESS(aws_hash_table_find(&hdr.enc_ctx, empty, &pElem));
    TEST_ASSERT_ADDR_NOT_NULL(pElem);
    TEST_ASSERT(aws_string_eq(pElem->value, empty));

    // EDK checks
    struct aws_cryptosdk_edk edk;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&hdr.edk_list, &edk, 0));
    TEST_ASSERT_INT_EQ(0, edk.provider_id.len);
    TEST_ASSERT_INT_EQ(0, edk.provider_info.len);
    TEST_ASSERT_INT_EQ(0, edk.ciphertext.len);

    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&hdr.edk_list, &edk, 2));
    TEST_ASSERT_INT_EQ(0, edk.provider_id.len);
    TEST_ASSERT_INT_EQ(0, edk.provider_info.len);
    TEST_ASSERT_INT_EQ(0, edk.ciphertext.len);

    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&hdr.edk_list, &edk, 1));
    TEST_ASSERT_BUF_EQ(edk.provider_id, 0x10, 0x11, 0x12, 0x00);
    TEST_ASSERT_BUF_EQ(edk.provider_info, 0x01, 0x02, 0x03, 0x04);
    TEST_ASSERT_BUF_EQ(edk.ciphertext, 0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88);

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), hdr.auth_len + hdr.auth_tag.len + hdr.iv.len);

    aws_cryptosdk_hdr_clean_up(&hdr);
    return 0;
}

int simple_headerV2_parse() {
    struct aws_cryptosdk_hdr hdr;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(test_headerV2_1, sizeof(test_headerV2_1) - 1);

    TEST_ASSERT_SUCCESS(aws_cryptosdk_hdr_init(&hdr, aws_default_allocator()));
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_parse(&hdr, &cursor));
    TEST_ASSERT_INT_EQ(cursor.len, 0);
    TEST_ASSERT_ADDR_EQ(cursor.ptr, test_headerV2_1 + sizeof(test_headerV2_1) - 1);

    TEST_ASSERT_INT_EQ(hdr.alg_id, ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY);

    TEST_ASSERT_BUF_EQ(
        hdr.message_id,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f);

    // enc ctx / AAD
    AWS_STATIC_STRING_FROM_LITERAL(k0, "\x54\x65\x73\x74");
    AWS_STATIC_STRING_FROM_LITERAL(v0, "\x4f\x6e\x65");
    AWS_STATIC_STRING_FROM_LITERAL(k1, "\x54\x73\x73\x74");
    AWS_STATIC_STRING_FROM_LITERAL(v1, "\x54\x77\x6f");
    TEST_ASSERT_INT_EQ(2, aws_hash_table_get_entry_count(&hdr.enc_ctx));
    struct aws_hash_element *p_elem;
    TEST_ASSERT_SUCCESS(aws_hash_table_find(&hdr.enc_ctx, k0, &p_elem));
    TEST_ASSERT_ADDR_NOT_NULL(p_elem);
    TEST_ASSERT(aws_string_eq(p_elem->value, v0));
    TEST_ASSERT_SUCCESS(aws_hash_table_find(&hdr.enc_ctx, k1, &p_elem));
    TEST_ASSERT_ADDR_NOT_NULL(p_elem);
    TEST_ASSERT(aws_string_eq(p_elem->value, v1));

    // EDKs
    TEST_ASSERT_INT_EQ(1, aws_array_list_length(&hdr.edk_list));
    struct aws_cryptosdk_edk edk;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&hdr.edk_list, &edk, 0));
    TEST_ASSERT_BUF_EQ(edk.provider_id, 0x50, 0x72, 0x6f, 0x76);
    TEST_ASSERT_BUF_EQ(edk.provider_info, 0x49, 0x6e, 0x66, 0x6f);
    TEST_ASSERT_BUF_EQ(
        edk.ciphertext, 0x59, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x53, 0x75, 0x62, 0x6d, 0x61, 0x72, 0x69, 0x6e, 0x65);

    TEST_ASSERT_INT_EQ(0x1000, hdr.frame_len);

    TEST_ASSERT_BUF_EQ(
        hdr.alg_suite_data,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1a,
        0x1b,
        0x1c,
        0x1d,
        0x1e,
        0x1f,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f);

    TEST_ASSERT_INT_EQ(hdr.auth_len, sizeof(test_headerV2_1) - 1 - 16);  // 1 junk byte, 16 auth tag bytes
    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), hdr.auth_len + hdr.auth_tag.len);
    TEST_ASSERT_INT_EQ(0, hdr.iv.len);

    aws_cryptosdk_hdr_clean_up(&hdr);
    return 0;
}

int simple_header_parse2() {
    struct aws_cryptosdk_hdr hdr;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(test_header_2, sizeof(test_header_2));

    TEST_ASSERT_SUCCESS(aws_cryptosdk_hdr_init(&hdr, aws_default_allocator()));
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_parse(&hdr, &cursor));
    // There should be one byte of trailing data left over
    TEST_ASSERT_INT_EQ(cursor.len, 1);

    // Known answer tests
    TEST_ASSERT_INT_EQ(hdr.alg_id, ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256);

    struct aws_byte_cursor message_id = aws_byte_cursor_from_buf(&hdr.message_id);
    TEST_ASSERT_CUR_EQ(
        message_id, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);

    TEST_ASSERT_BUF_EQ(hdr.iv, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b);

    TEST_ASSERT_BUF_EQ(
        hdr.auth_tag, 0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef);

    // Misc values
    TEST_ASSERT_INT_EQ(0, aws_hash_table_get_entry_count(&hdr.enc_ctx));
    TEST_ASSERT_INT_EQ(3, aws_array_list_length(&hdr.edk_list));
    TEST_ASSERT_INT_EQ(0x1000, hdr.frame_len);
    TEST_ASSERT_INT_EQ(hdr.auth_len, sizeof(test_header_2) - 29);  // 1 junk byte, 12 IV bytes, 16 auth tag bytes

    // EDK checks
    struct aws_cryptosdk_edk edk;
    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&hdr.edk_list, &edk, 0));
    TEST_ASSERT_INT_EQ(0, edk.provider_id.len);
    TEST_ASSERT_INT_EQ(0, edk.provider_info.len);
    TEST_ASSERT_INT_EQ(0, edk.ciphertext.len);

    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&hdr.edk_list, &edk, 2));
    TEST_ASSERT_INT_EQ(0, edk.provider_id.len);
    TEST_ASSERT_INT_EQ(0, edk.provider_info.len);
    TEST_ASSERT_INT_EQ(0, edk.ciphertext.len);

    TEST_ASSERT_SUCCESS(aws_array_list_get_at(&hdr.edk_list, &edk, 1));
    TEST_ASSERT_BUF_EQ(edk.provider_id, 0x10, 0x11, 0x12, 0x00);
    TEST_ASSERT_BUF_EQ(edk.provider_info, 0x01, 0x02, 0x03, 0x04);
    TEST_ASSERT_BUF_EQ(edk.ciphertext, 0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88);

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), hdr.auth_len + hdr.auth_tag.len + hdr.iv.len);

    aws_cryptosdk_hdr_clean_up(&hdr);
    return 0;
}

int failed_parse() {
    // incomplete header
    struct aws_cryptosdk_hdr hdr;
    struct aws_byte_cursor cursor;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_hdr_init(&hdr, aws_default_allocator()));

    cursor = aws_byte_cursor_from_array(test_header_1, sizeof(test_header_1) - 5);
    TEST_ASSERT_ERROR(AWS_ERROR_SHORT_BUFFER, aws_cryptosdk_hdr_parse(&hdr, &cursor));
    TEST_ASSERT_ADDR_EQ(cursor.ptr, test_header_1);

    TEST_ASSERT_INT_EQ(0, hdr.alg_id);

    // faulty header
    size_t num_bad_hdrs = sizeof(bad_headers) / sizeof(uint8_t *);

    for (size_t hdr_idx = 0; hdr_idx < num_bad_hdrs; ++hdr_idx) {
        cursor = aws_byte_cursor_from_array(bad_headers[hdr_idx], bad_headers_sz[hdr_idx]);

        TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT, aws_cryptosdk_hdr_parse(&hdr, &cursor));
        TEST_ASSERT_ADDR_EQ(cursor.ptr, bad_headers[hdr_idx]);

        TEST_ASSERT_INT_EQ(0, hdr.alg_id);
    }

    aws_cryptosdk_hdr_clean_up(&hdr);

    return 0;
}

#ifdef _POSIX_VERSION
// Returns the amount of padding needed to align len to a multiple of
// the system page size.
static size_t page_padding(size_t len) {
    size_t pagesize = sysconf(_SC_PAGESIZE);
    return -len % pagesize;
}

// Tests that we don't overread past the end of the buffer.
// Optionally (if flip_bit_index >= 0 && < inlen * 8), flips a bit in the header buffer.
static void overread_once(const uint8_t *inbuf, size_t inlen, ssize_t flip_bit_index) {
    // Copy the header to a buffer aligned at the end of a page, and just before the subsequent page

    // First, round up to at least size + one page, page aligned.
    int pagesize      = sysconf(_SC_PAGESIZE);
    size_t offset     = page_padding(inlen);
    size_t total_size = offset + inlen + pagesize;

    // We now set up a memory layout looking like the following:
    // [padding] [header] [inaccessible page]
    uint8_t *pbuffer = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pbuffer == MAP_FAILED) {
        perror("mmap");
        abort();
    }

    uint8_t *phdr  = pbuffer + offset;
    uint8_t *ptrap = phdr + inlen;

    memcpy(phdr, inbuf, inlen);
    if (mprotect(ptrap, pagesize, PROT_NONE)) {
        perror("mprotect");
        abort();
    }

    size_t byte_offset = flip_bit_index >> 3;
    if (flip_bit_index >= 0 && byte_offset < inlen) {
        int bit_offset = flip_bit_index & 7;
        phdr[byte_offset] ^= (1 << bit_offset);
    }

    struct aws_cryptosdk_hdr hdr;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(phdr, inlen);

    aws_cryptosdk_hdr_init(&hdr, aws_default_allocator());
    // We don't care about the return value as long as we don't actually crash.
    aws_cryptosdk_hdr_parse(&hdr, &cursor);
    aws_cryptosdk_hdr_clean_up(&hdr);

    // This is only necessary when aws_cryptosdk_hdr_parse_init succeeds,
    // but including it all the time is also a good test that we have made
    // aws_cryptosdk_hdr_clean_up idempotent.
    aws_cryptosdk_hdr_clean_up(&hdr);
    munmap(pbuffer, total_size);
}

static int overread() {
    // Test that various truncations don't result in an overread
    for (size_t hdrlen = 0; hdrlen < sizeof(test_header_1); hdrlen++) {
        overread_once(test_header_1, hdrlen, -1);
    }

    // Test that corrupt header fields don't result in an overread
    for (size_t flipbit = 0; flipbit < sizeof(test_header_1) << 3; flipbit++) {
        overread_once(test_header_1, sizeof(test_header_1), flipbit);
    }
    return 0;
}

#else  // _POSIX_VERSION
static int overread() {
    fprintf(stderr, "[SKIPPED] header.overread - not implemented on windows");
    return 0;  // can't do overread tests portably
}
#endif

int header_size() {
    struct aws_cryptosdk_hdr hdr = test_header_1_hdr();

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), sizeof(test_header_1) - 1);

    // Now test that hdr_size detects integer overflow
    for (size_t i = 0; i < aws_array_list_length(&hdr.edk_list); i++) {
        struct aws_cryptosdk_edk *edk = NULL;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&hdr.edk_list, (void **)&edk, i));

        edk->ciphertext.len    = SIZE_MAX >> 1;
        edk->provider_id.len   = SIZE_MAX >> 1;
        edk->provider_info.len = SIZE_MAX >> 1;
    }

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), 0);

    // Reset the edk to validity before doing cleanup.
    for (size_t i = 0; i < aws_array_list_length(&hdr.edk_list); i++) {
        struct aws_cryptosdk_edk *edk = NULL;
        TEST_ASSERT_SUCCESS(aws_array_list_get_at_ptr(&hdr.edk_list, (void **)&edk, i));

        edk->ciphertext.len    = 0;
        edk->provider_id.len   = 0;
        edk->provider_info.len = 0;
    }

    aws_cryptosdk_hdr_clean_up(&hdr);

    return 0;
}

int simple_header_write() {
    struct aws_cryptosdk_hdr hdr = test_header_1_hdr();

    size_t outlen   = sizeof(test_header_1) - 1;  // not including junk byte
    uint8_t *outbuf = alloca(outlen);
    size_t bytes_written;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_hdr_write(&hdr, &bytes_written, outbuf, outlen));
    TEST_ASSERT_INT_EQ(bytes_written, outlen);
    TEST_ASSERT(!memcmp(test_header_1, outbuf, outlen));

    aws_cryptosdk_hdr_clean_up(&hdr);

    hdr = test_header_2_hdr();

    size_t outlen2   = sizeof(test_header_2) - 1;
    uint8_t *outbuf2 = alloca(outlen2);
    size_t bytes_written2;

    TEST_ASSERT_SUCCESS(aws_cryptosdk_hdr_write(&hdr, &bytes_written2, outbuf2, outlen2));
    TEST_ASSERT_INT_EQ(bytes_written2, outlen2);
    TEST_ASSERT(!memcmp(test_header_2, outbuf2, outlen2));

    aws_cryptosdk_hdr_clean_up(&hdr);

    return 0;
}

int header_failed_write() {
    struct aws_cryptosdk_hdr hdr = test_header_1_hdr();

    size_t outlen   = sizeof(test_header_1) - 2;
    uint8_t *outbuf = alloca(outlen);
    size_t bytes_written;
    memset(outbuf, 'A', outlen);

    TEST_ASSERT_INT_NE(AWS_OP_SUCCESS, aws_cryptosdk_hdr_write(&hdr, &bytes_written, outbuf, outlen));
    TEST_ASSERT_INT_EQ(bytes_written, 0);
    for (size_t idx = 0; idx < outlen; ++idx) {
        TEST_ASSERT_INT_EQ(outbuf[idx], 0);
    }

    aws_cryptosdk_hdr_clean_up(&hdr);

    return 0;
}

// If alg ID is unknown, _hdr_write should return ERR_BAD_STATE
int header_unsupported_alg_id_failed_write() {
    struct aws_cryptosdk_hdr hdr = test_headerV2_1_hdr();
    hdr.alg_id                   = 0xfaff;
    size_t outlen                = sizeof(test_headerV2_1) - 1;  // not including junk byte
    uint8_t *outbuf              = alloca(outlen);
    size_t bytes_written;
    TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_STATE, aws_cryptosdk_hdr_write(&hdr, &bytes_written, outbuf, outlen));
    aws_cryptosdk_hdr_clean_up(&hdr);
    return 0;
}

int simple_headerV2_write() {
    struct aws_cryptosdk_hdr hdr = test_headerV2_1_hdr();
    size_t outlen                = sizeof(test_headerV2_1) - 1;  // not including junk byte
    uint8_t *outbuf              = alloca(outlen);
    size_t bytes_written;
    TEST_ASSERT_SUCCESS(aws_cryptosdk_hdr_write(&hdr, &bytes_written, outbuf, outlen));
    TEST_ASSERT_INT_EQ(bytes_written, outlen);
    TEST_ASSERT(!memcmp(test_headerV2_1, outbuf, outlen));
    aws_cryptosdk_hdr_clean_up(&hdr);
    return 0;
}

#ifdef _POSIX_VERSION
int overwrite() {
    struct aws_cryptosdk_hdr hdr1 = test_header_1_hdr();
    struct aws_cryptosdk_hdr hdr2 = test_header_2_hdr();

    struct aws_cryptosdk_hdr *test_headers[2];
    test_headers[0] = &hdr1;
    test_headers[1] = &hdr2;

    int pagesize = sysconf(_SC_PAGESIZE);

    for (size_t idx = 0; idx < sizeof(test_headers) / sizeof(struct aws_cryptosdk_hdr *); ++idx) {
        size_t bytes_written;

        int header_len = aws_cryptosdk_hdr_size(test_headers[idx]);

        // First, round up to at least size + one page, page aligned.
        size_t offset     = page_padding(header_len);
        size_t total_size = offset + header_len + pagesize;

        // We now set up a memory layout looking like the following:
        // [padding] [header] [inaccessible page]
        uint8_t *pbuffer = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pbuffer == MAP_FAILED) {
            perror("mmap");
            abort();
        }

        uint8_t *phdr  = pbuffer + offset;
        uint8_t *ptrap = phdr + header_len;

        if (mprotect(ptrap, pagesize, PROT_NONE)) {
            perror("mprotect");
            abort();
        }

        aws_cryptosdk_hdr_write(test_headers[idx], &bytes_written, phdr, header_len + pagesize);
        munmap(pbuffer, total_size);
    }

    aws_cryptosdk_hdr_clean_up(&hdr1);
    aws_cryptosdk_hdr_clean_up(&hdr2);

    return 0;
}
#else
int overwrite() {
    fprintf(stderr, "[SKIPPED] header.overwrite - not implemented on windows");
    return 0;
}
#endif

struct test_case header_test_cases[] = {
    { "header", "parse", simple_header_parse },
    { "header", "parseHeaderV2", simple_headerV2_parse },
    { "header", "parse2", simple_header_parse2 },
    { "header", "failed_parse", failed_parse },
    { "header", "overread", overread },
    { "header", "size", header_size },
    { "header", "write", simple_header_write },
    { "header", "failed_write", header_failed_write },
    { "header", "unsupported_alg_id_write", header_unsupported_alg_id_failed_write },
    { "header", "writeHeaderV2", simple_headerV2_write },
    { "header", "overwrite", overwrite },
    { NULL }
};
