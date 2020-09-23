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

#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/private/header.h>
#include "testutil.h"

#include <stdlib.h>
#include "testing.h"
#include "testutil.h"

#ifdef _MSC_VER
#    include <malloc.h>
#    define alloca _alloca
#endif

static int test_kdf_committing(
    enum aws_cryptosdk_alg_id alg_id,
    const char *msg_id,
    const char *data_key,
    const char *expected_key_str,
    const char *expected_commitment_str) {
    struct aws_byte_buf data_key_buf = easy_b64_decode(data_key);
    struct data_key key;

    assert(data_key_buf.len == sizeof(key.keybuf));
    memcpy(key.keybuf, data_key_buf.buffer, data_key_buf.len);

    aws_byte_buf_clean_up_secure(&data_key_buf);

    struct aws_byte_buf msgid_buf = easy_b64_decode(msg_id);
    assert(msgid_buf.len == 32);

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    struct aws_byte_buf commitment;

    struct content_key key_out = { { 0 } };

    if (aws_byte_buf_init(&commitment, aws_default_allocator(), props->commitment_len)) abort();

    struct aws_byte_buf expected_key    = easy_b64_decode(expected_key_str);
    struct aws_byte_buf expected_commit = easy_b64_decode(expected_commitment_str);

    TEST_ASSERT_INT_EQ(
        AWS_OP_SUCCESS,
        aws_cryptosdk_private_derive_key(aws_cryptosdk_alg_props(alg_id), &key_out, &key, &commitment, &msgid_buf));

    if (expected_key.len != props->content_key_len ||
        memcmp(expected_key.buffer, key_out.keybuf, props->content_key_len)) {
        struct aws_string *str = easy_b64_encode(key_out.keybuf, props->content_key_len);
        fprintf(stderr, "Unexpected data key: Expected {%s} got {%s}\n", expected_key_str, str->bytes);
        aws_string_destroy(str);
    }

    if (expected_commit.len != props->commitment_len ||
        memcmp(expected_commit.buffer, commitment.buffer, props->commitment_len)) {
        struct aws_string *str = easy_b64_encode(commitment.buffer, props->commitment_len);
        fprintf(stderr, "Unexpected commitment: Expected {%s} got {%s}\n", expected_commitment_str, str->bytes);
        aws_string_destroy(str);
    }

    TEST_ASSERT_INT_EQ(props->content_key_len, expected_key.len);
    TEST_ASSERT_INT_EQ(props->commitment_len, expected_commit.len);
    TEST_ASSERT_INT_EQ(0, memcmp(key_out.keybuf, expected_key.buffer, props->content_key_len));
    TEST_ASSERT_INT_EQ(0, memcmp(commitment.buffer, expected_commit.buffer, props->commitment_len));

    aws_byte_buf_clean_up(&expected_commit);
    aws_byte_buf_clean_up(&expected_key);
    aws_byte_buf_clean_up(&commitment);
    aws_byte_buf_clean_up(&msgid_buf);

    return 0;
}

static int test_kdf() {
    static const struct data_key key   = { { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                           0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                           0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f } };
    static const uint8_t msgid[16]     = { 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                                       0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
    struct aws_byte_buf msgid_buf      = aws_byte_buf_from_array(msgid, sizeof(msgid));
    struct aws_byte_buf key_commitment = aws_byte_buf_from_array(msgid, 0);

    if (test_kdf_committing(
            ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY,
            "MzlttCC+7kgGqr+24I4GB+njRl14Njecy9Adm0UrggQ=",  // message id
            "vygtxterAtNjVoXCpsoxdgAorgJCLj61QiFpqpoUu5k=",  // data key
            "U5U2XRpCt3ZGvAYL8ZGgi1ofTzyDnrywnLkbyQzK5EI=",  // content key
            "wGXUCB4Zox9NKaJSi+QNu8ve712ct1/VPT6leVovkrU=")  // commitment
    )
        return 1;
    if (test_kdf_committing(
            ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
            "MzlttCC+7kgGqr+24I4GB+njRl14Njecy9Adm0UrggQ=",
            "vygtxterAtNjVoXCpsoxdgAorgJCLj61QiFpqpoUu5k=",
            "zFPKfCoowtpjsaApxPP9VtMOtgaDkf7oCI4B7BX95u0=",
            "wGXUCB4Zox9NKaJSi+QNu8ve712ct1/VPT6leVovkrU="))
        return 1;

#define ASSERT_KDF(alg_id, ...)                                                                 \
    do {                                                                                        \
        uint8_t expected[MAX_DATA_KEY_SIZE + 1] = { __VA_ARGS__, 0 };                           \
        struct content_key key_out              = { { 0 } };                                    \
        TEST_ASSERT_INT_EQ(                                                                     \
            AWS_OP_SUCCESS,                                                                     \
            aws_cryptosdk_private_derive_key(                                                   \
                aws_cryptosdk_alg_props(alg_id), &key_out, &key, &key_commitment, &msgid_buf)); \
        TEST_ASSERT_INT_EQ(0, memcmp(key_out.keybuf, expected, MAX_DATA_KEY_SIZE));             \
    } while (0)

    // clang-format off
    ASSERT_KDF(ALG_AES128_GCM_IV12_TAG16_NO_KDF,
                     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f );
    ASSERT_KDF(ALG_AES192_GCM_IV12_TAG16_NO_KDF,
                     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 );
    ASSERT_KDF(ALG_AES256_GCM_IV12_TAG16_NO_KDF,
                     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f );
    ASSERT_KDF(ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
                     0xb0, 0xaf, 0xe9, 0xc5, 0x02, 0xb1, 0xf5, 0xe4, 0x52, 0x42, 0xf9, 0xc4, 0x0a, 0xaa, 0x96, 0x66 );
    ASSERT_KDF(ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
                     0x8d, 0x5c, 0xd4, 0x89, 0x05, 0xb2, 0x78, 0x19, 0x74, 0xc0, 0x0a, 0xa4, 0x10, 0x28, 0xc9, 0x36, 0xfe, 0x5c, 0xe8, 0xc0, 0xb0, 0x47, 0x38, 0x8d );
    ASSERT_KDF(ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
                     0xca, 0x63, 0x33, 0x7e, 0x0f, 0x1b, 0x51, 0xe6, 0xd8, 0xea, 0x2b, 0xba, 0x47, 0x68, 0x51, 0xaf, 0x81, 0xb9, 0xa1, 0xab, 0x61, 0x10, 0x65, 0x88, 0xa3, 0x68, 0xde, 0xbf, 0xde, 0x28, 0x15, 0x95 );
    ASSERT_KDF(ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
                     0xab, 0x7b, 0xa1, 0x53, 0x57, 0xc9, 0x60, 0x93, 0x12, 0x20, 0x05, 0x47, 0x6a, 0xdd, 0x8d, 0x20 );
    ASSERT_KDF(ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                     0x84, 0x28, 0xbd, 0x00, 0xaa, 0x47, 0xa0, 0x8d, 0xee, 0x53, 0x14, 0x58, 0x42, 0x7d, 0xd1, 0xa3, 0x31, 0x36, 0x67, 0xad, 0x0a, 0xeb, 0x06, 0xdf );
    ASSERT_KDF(ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                     0x9d, 0x46, 0xe2, 0x70, 0x9e, 0x59, 0x3e, 0xba, 0xae, 0x81, 0x70, 0x44, 0x16, 0xaf, 0x5d, 0xf9, 0x0c, 0x57, 0x5f, 0xa4, 0xdc, 0xf0, 0xda, 0x78, 0x11, 0x6b, 0x6b, 0x6d, 0x59, 0x9d, 0xe6, 0x2c );
    // clang-format on

    return 0;
}

static int test_decrypt_frame_aad() {
    {
        struct content_key key = {
            { 0xdd, 0xd0, 0x36, 0x6d, 0xb2, 0x59, 0xa9, 0xef, 0x22, 0x6b, 0x03, 0x8c, 0x91, 0xe2, 0x05, 0x1f, 0 }
        };
        uint8_t messageId_arr[]       = { 0x22, 0x9b, 0xf1, 0x19, 0x2e, 0xf2, 0x94, 0x32,
                                    0x28, 0x72, 0x9d, 0xfd, 0x93, 0x98, 0x9b, 0x45 };
        struct aws_byte_buf messageId = aws_byte_buf_from_array(messageId_arr, sizeof(messageId_arr));

        uint8_t plaintext[]                 = { 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64 };
        uint8_t zero_buf[sizeof(plaintext)] = { 0 };
        uint32_t seqno                      = 1;
        uint8_t iv[]         = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        uint8_t ciphertext[] = { 0x6a, 0x76, 0x63, 0x83, 0xbc, 0x7e, 0x6e, 0x2c, 0x2d, 0x9e, 0x41 };
        uint8_t tag[]        = {
            0xdf, 0x65, 0x40, 0x39, 0xcc, 0x98, 0xa7, 0xa1, 0xde, 0x91, 0x60, 0x2e, 0x46, 0x49, 0x23, 0xc1
        };
        uint8_t actual[11]        = { 0 };
        struct aws_byte_cursor in = aws_byte_cursor_from_array(ciphertext, sizeof(ciphertext));
        struct aws_byte_buf out   = aws_byte_buf_from_empty_array(actual, sizeof(actual));

        TEST_ASSERT_INT_EQ(
            AWS_OP_SUCCESS,
            aws_cryptosdk_decrypt_body(
                aws_cryptosdk_alg_props(ALG_AES128_GCM_IV12_TAG16_NO_KDF),
                &out,
                &in,
                &messageId,
                seqno,
                iv,
                &key,
                tag,
                FRAME_TYPE_FRAME));
        TEST_ASSERT_INT_EQ(0, memcmp(plaintext, actual, sizeof(plaintext)));

        // Verify that we are checking the tag
        messageId.buffer[0]++;
        out.len = 0;
        TEST_ASSERT_INT_EQ(
            AWS_OP_ERR,
            aws_cryptosdk_decrypt_body(
                aws_cryptosdk_alg_props(ALG_AES128_GCM_IV12_TAG16_NO_KDF),
                &out,
                &in,
                &messageId,
                seqno,
                iv,
                &key,
                tag,
                FRAME_TYPE_FRAME));
        TEST_ASSERT_INT_EQ(0, memcmp(zero_buf, actual, sizeof(zero_buf)));
        messageId.buffer[0]--;

        tag[0]++;
        out.len = 0;
        TEST_ASSERT_INT_EQ(
            AWS_OP_ERR,
            aws_cryptosdk_decrypt_body(
                aws_cryptosdk_alg_props(ALG_AES128_GCM_IV12_TAG16_NO_KDF),
                &out,
                &in,
                &messageId,
                seqno,
                iv,
                &key,
                tag,
                FRAME_TYPE_FRAME));
        TEST_ASSERT_INT_EQ(0, memcmp(zero_buf, actual, sizeof(zero_buf)));
        tag[0]--;
    }

    return 0;
}

static int test_frame_enc_dec(
    enum aws_cryptosdk_alg_id alg_id,
    const char *ct_b64,
    const char *pt_b64,
    const char *msgid_b64,
    const char *content_key_b64,
    uint32_t seqno,
    const char *iv_b64,
    const char *tag_b64,
    enum aws_cryptosdk_frame_type frame_type) {
    int failed = 0;

    const struct aws_cryptosdk_alg_properties *props = aws_cryptosdk_alg_props(alg_id);

    struct aws_byte_buf ciphertext      = easy_b64_decode(ct_b64);
    struct aws_byte_buf plaintext       = easy_b64_decode(pt_b64);
    struct aws_byte_buf msgid           = easy_b64_decode(msgid_b64);
    struct aws_byte_buf content_key_buf = easy_b64_decode(content_key_b64);

    struct content_key content_key;
    assert(content_key_buf.len <= sizeof(content_key.keybuf));
    memcpy(&content_key.keybuf, content_key_buf.buffer, content_key_buf.len);

    struct aws_byte_buf iv  = easy_b64_decode(iv_b64);
    struct aws_byte_buf tag = easy_b64_decode(tag_b64);

    struct aws_byte_cursor in;
    struct aws_byte_buf out;

    uint8_t out_tag[16];
    uint8_t out_iv[12];

    if (aws_byte_buf_init(&out, aws_default_allocator(), ciphertext.len)) abort();

    in = aws_byte_cursor_from_buf(&plaintext);
    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_encrypt_body(props, &out, &in, &msgid, seqno, out_iv, &content_key, out_tag, frame_type));

    if (out.len != ciphertext.len || memcmp(out.buffer, ciphertext.buffer, out.len)) {
        struct aws_string *out_b64 = easy_b64_encode(out.buffer, out.len);

        fprintf(
            stderr, "[%s] Ciphertext mismatch; expected={%s} computed={%s}\n", props->alg_name, ct_b64, out_b64->bytes);

        aws_string_destroy(out_b64);
        failed = 1;
    }

    if (tag.len != sizeof(out_tag) || memcmp(tag.buffer, out_tag, tag.len)) {
        struct aws_string *out_b64 = easy_b64_encode(out_tag, sizeof(out_tag));

        fprintf(stderr, "[%s] Tag mismatch; expected={%s} computed={%s}\n", props->alg_name, tag_b64, out_b64->bytes);

        aws_string_destroy(out_b64);
        failed = 1;
    }

    if (iv.len != sizeof(out_iv) || memcmp(iv.buffer, out_iv, iv.len)) {
        struct aws_string *out_b64 = easy_b64_encode(out_iv, sizeof(out_iv));

        fprintf(stderr, "[%s] Tag mismatch; expected={%s} computed={%s}\n", props->alg_name, iv_b64, out_b64->bytes);

        aws_string_destroy(out_b64);
        failed = 1;
    }

    in      = aws_byte_cursor_from_buf(&ciphertext);
    out.len = 0;

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_decrypt_body(props, &out, &in, &msgid, seqno, iv.buffer, &content_key, tag.buffer, frame_type));
    TEST_ASSERT(aws_byte_buf_eq(&out, &plaintext));

    aws_byte_buf_clean_up(&ciphertext);
    aws_byte_buf_clean_up(&plaintext);
    aws_byte_buf_clean_up(&msgid);
    aws_byte_buf_clean_up(&content_key_buf);
    aws_byte_buf_clean_up(&iv);
    aws_byte_buf_clean_up(&tag);
    aws_byte_buf_clean_up(&out);

    return failed;
}

static int test_decrypt_frame_all_algos() {
    if (test_frame_enc_dec(
            ALG_AES128_GCM_IV12_TAG16_NO_KDF,
            "6+X0tH/udz3po3I=",          // Ciphertext
            "aGVsbG8gd29ybGQ=",          // Plaintext
            "GmbY4A0w6z0Ur1u2acQJvA==",  // Message ID
            "Vaiyu0QnEDG3NDuACP6tUg==",  // Content key
            1,                           // seqno
            "AAAAAAAAAAAAAAAB",          // IV
            "D7AH1DcNdSriUu//oId+Xg==",  // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES192_GCM_IV12_TAG16_NO_KDF,
            "Lo+MghJ/Shrb0yY=",                  // Ciphertext
            "aGVsbG8gd29ybGQ=",                  // Plaintext
            "vNDsYQw93Du4Mo+00Dj5Ow==",          // Message ID
            "OdEbpimzNZh6IYwE7E8rptSOZltxivfl",  // Content key
            1,                                   // seqno
            "AAAAAAAAAAAAAAAB",                  // IV
            "cbZ4WDg/xskxwKgT6xd5UA==",          // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES256_GCM_IV12_TAG16_NO_KDF,
            "0n/BERrHCZAF9Jo=",                              // Ciphertext
            "aGVsbG8gd29ybGQ=",                              // Plaintext
            "0HkxM0/+0uF1PlnNM/J4Sg==",                      // Message ID
            "yh3gGVV7kmuGjCXrKBw/FEIz/L0dztZx0GMMu2FW/e8=",  // Content key
            1,                                               // seqno
            "AAAAAAAAAAAAAAAB",                              // IV
            "nT8612Y+tXELpIk+OVPR+g==",                      // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
            "r14niZg76kUXcHo=",          // Ciphertext
            "aGVsbG8gd29ybGQ=",          // Plaintext
            "QhmgMgrEveiJ5M1VHeUUcQ==",  // Message ID
            "rCDKV0IuFGRaAxkZfaEZFA==",  // Content key
            1,                           // seqno
            "AAAAAAAAAAAAAAAB",          // IV
            "EH8zLklzwSUdtBKZ8va3iw==",  // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
            "gj+QsEDmBD2zens=",                              // Ciphertext
            "aGVsbG8gd29ybGQ=",                              // Plaintext
            "YdHM8j4cj6NuVl/30Cl6xg==",                      // Message ID
            "vsoLkqPZphVbPY1/A3ZmW7r1A5vXmad6yJEzT4oT1qM=",  // Content key
            1,                                               // seqno
            "AAAAAAAAAAAAAAAB",                              // IV
            "xv9j2k3WAO7h39iyz0Suww==",                      // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
            "DJUsN/Xjns8MVkw=",                  // Ciphertext
            "aGVsbG8gd29ybGQ=",                  // Plaintext
            "39MDhMRVihe1KdgudT4ugQ==",          // Message ID
            "Pnc3AhR2RH624UKK6sX059DouNlIU4y+",  // Content key
            1,                                   // seqno
            "AAAAAAAAAAAAAAAB",                  // IV
            "W/kpLa4uEhqGzd2eWMLTAA==",          // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            "FsAyXSjqSbROjh0=",                  // Ciphertext
            "aGVsbG8gd29ybGQ=",                  // Plaintext
            "FT+yKarIM4qWkpCOEwIrkQ==",          // Message ID
            "fytiRTYsXEZcXg+zNusn8XAR+Kef4qev",  // Content key
            1,                                   // seqno
            "AAAAAAAAAAAAAAAB",                  // IV
            "ns/I9uXquXRDem0Rtuc4Vg==",          // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
            "IfbRB45NL5Uum54=",          // Ciphertext
            "aGVsbG8gd29ybGQ=",          // Plaintext
            "Nrv5EP/n8vdsQSYtp0Sj0g==",  // Message ID
            "LnqalIiqU8aCdMx+435G8Q==",  // Content key
            1,                           // seqno
            "AAAAAAAAAAAAAAAB",          // IV
            "4aAO3lN76vT8kMl3EXT5Jw==",  // Tag
            FRAME_TYPE_FRAME))
        return 1;
    if (test_frame_enc_dec(
            ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            "Ou2nJ5/AquIiNJc=",                              // Ciphertext
            "aGVsbG8gd29ybGQ=",                              // Plaintext
            "gLyFFYF5Z49aM10E2g2DMg==",                      // Message ID
            "160eBTIuRmIOzPx61sgz8HcW5GQfqLDnNBsUCWcS17Y=",  // Content key
            1,                                               // seqno
            "AAAAAAAAAAAAAAAB",                              // IV
            "dmAjv/N+C4CN4elZMiZ55w==",                      // Tag
            FRAME_TYPE_FRAME))
        return 1;

    return 0;
}

static int testHeaderAuth(
    const uint8_t *header,
    size_t headerlen,
    const uint8_t *authtag,
    size_t taglen,
    const uint8_t *key,
    enum aws_cryptosdk_alg_id alg_id) {
    struct content_key derived_key;
    struct data_key data_key;

    const struct aws_cryptosdk_alg_properties *alg = aws_cryptosdk_alg_props(alg_id);
    struct aws_allocator *alloc                    = aws_default_allocator();

    // We assume our test vector keys are appropriately sized
    memcpy(data_key.keybuf, key, sizeof(data_key.keybuf));

    // XXX: Properly parse header instead of blindly getting the message ID from it
    struct aws_byte_buf msgid;

    if (alg->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_1_0) {
        msgid = aws_byte_buf_from_array(header + 4, 16);
    } else {
        msgid = aws_byte_buf_from_array(header + 3, 32);
    }
    struct aws_byte_buf key_commitment;
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(&key_commitment, aws_default_allocator(), alg->commitment_len));

    TEST_ASSERT_INT_EQ(
        AWS_OP_SUCCESS, aws_cryptosdk_private_derive_key(alg, &derived_key, &data_key, &key_commitment, &msgid));

    struct aws_byte_buf headerbuf = aws_byte_buf_from_array(header, headerlen);
    struct aws_byte_buf authbuf   = aws_byte_buf_from_array(authtag, taglen);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_verify_header(alg, &derived_key, &authbuf, &headerbuf));

    uint8_t *badheader = alloca(headerlen);
    headerbuf.buffer   = badheader;

    for (size_t i = 0; i < headerlen * 8; i++) {
        memcpy(badheader, header, headerlen);
        badheader[i / 8] ^= (1 << (i % 8));

        TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_verify_header(alg, &derived_key, &authbuf, &headerbuf));
    }

    uint8_t *badtag  = alloca(taglen);
    headerbuf.buffer = (uint8_t *)header;
    authbuf.buffer   = badtag;

    for (size_t i = 0; i < taglen * 8; i++) {
        memcpy(badtag, authtag, taglen);
        badtag[i / 8] ^= (1 << (i % 8));

        TEST_ASSERT_INT_EQ(AWS_OP_ERR, aws_cryptosdk_verify_header(alg, &derived_key, &authbuf, &headerbuf));
    }

    aws_byte_buf_clean_up(&key_commitment);

    return 0;
}

static int test_verify_header() {
    {
        static const uint8_t header[]  = { 0x01, 0x80, 0x00, 0x14, 0xfb, 0xb2, 0xad, 0xb6, 0xc9, 0x67, 0xe1,
                                          0x8f, 0xe2, 0x24, 0x9b, 0x07, 0xda, 0xf0, 0x72, 0x76, 0x00, 0x00,
                                          0x00, 0x01, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00 };
        static const uint8_t authtag[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x02, 0x3f, 0x45, 0x60, 0x69, 0xf5, 0x3c, 0xdc,
                                           0x73, 0x32, 0x2b, 0x1e, 0x27, 0x6c, 0x39, 0x25 };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0x62, 0x96, 0xd9, 0x52, 0x67, 0x10, 0xfd, 0xc7,
                                                        0xa1, 0xb7, 0xa5, 0xcd, 0xe4, 0xe0, 0x76, 0x4c };
        if (testHeaderAuth(header, sizeof(header), authtag, sizeof(authtag), key, ALG_AES128_GCM_IV12_TAG16_NO_KDF))
            return 1;
    }
    {
        static const uint8_t header[]  = { 0x01, 0x80, 0x00, 0x46, 0x06, 0x10, 0xdc, 0x69, 0x68, 0x0a, 0x52,
                                          0x01, 0xdf, 0x15, 0x4d, 0x41, 0xc6, 0x5a, 0x18, 0x89, 0x00, 0x00,
                                          0x00, 0x01, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00 };
        static const uint8_t authtag[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0xeb, 0x18, 0xa3, 0x61, 0xab, 0x25, 0x07, 0xfb,
                                           0x2c, 0x12, 0x8b, 0x5f, 0x58, 0x8f, 0x06, 0xed };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0x3c, 0x5c, 0xae, 0xc5, 0x38, 0xcf, 0x0a, 0x06,
                                                        0x13, 0x01, 0x11, 0x0e, 0x4d, 0x66, 0xda, 0xff,
                                                        0xf0, 0x2a, 0xbd, 0x55, 0x2c, 0xbc, 0xa9, 0xa5 };
        if (testHeaderAuth(header, sizeof(header), authtag, sizeof(authtag), key, ALG_AES192_GCM_IV12_TAG16_NO_KDF))
            return 1;
    }
    {
        static const uint8_t header[]  = { 0x01, 0x80, 0x00, 0x78, 0x55, 0x36, 0xbe, 0xea, 0xe3, 0x64, 0x37,
                                          0xa9, 0xb1, 0xbe, 0x2e, 0x62, 0x1b, 0x08, 0x1e, 0x3c, 0x00, 0x00,
                                          0x00, 0x01, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00 };
        static const uint8_t authtag[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0xaa, 0x7f, 0x16, 0xc9, 0x79, 0x88, 0xcf, 0x34,
                                           0x9f, 0x6d, 0xa2, 0x41, 0x73, 0xd2, 0x8e, 0x66 };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0xde, 0x57, 0x2a, 0xb1, 0xb7, 0xdf, 0x4f, 0x97,
                                                        0x27, 0xbc, 0x87, 0x7b, 0xcf, 0x80, 0x94, 0xe5,
                                                        0x9f, 0x14, 0x54, 0x8d, 0xd3, 0x4b, 0x67, 0xc2,
                                                        0x5e, 0x0b, 0xcb, 0xad, 0xa1, 0x30, 0xa2, 0xe8 };
        if (testHeaderAuth(header, sizeof(header), authtag, sizeof(authtag), key, ALG_AES256_GCM_IV12_TAG16_NO_KDF))
            return 1;
    }
    {
        static const uint8_t header[]  = { 0x01, 0x80, 0x01, 0x14, 0x17, 0xb3, 0xa9, 0x64, 0x34, 0x89, 0x7d,
                                          0x60, 0xcd, 0x7f, 0xf2, 0x85, 0x41, 0x4d, 0xc0, 0x3d, 0x00, 0x00,
                                          0x00, 0x01, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00 };
        static const uint8_t authtag[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0xb5, 0x4e, 0x19, 0x82, 0x2c, 0x09, 0xc9, 0x82,
                                           0x09, 0xc7, 0x63, 0x0c, 0x7f, 0x4c, 0xc6, 0xf7 };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0xeb, 0x70, 0x9d, 0xf0, 0x34, 0x8a, 0x04, 0x09,
                                                        0x14, 0x33, 0x5d, 0x9e, 0x48, 0x75, 0xec, 0xaa };
        if (testHeaderAuth(
                header, sizeof(header), authtag, sizeof(authtag), key, ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256))
            return 1;
    }
    {
        static const uint8_t header[]  = { 0x01, 0x80, 0x01, 0x46, 0x82, 0x3b, 0x71, 0x2d, 0x5b, 0x84, 0xd3,
                                          0x8a, 0xda, 0x97, 0xdd, 0x97, 0x33, 0x99, 0x0f, 0x7a, 0x00, 0x00,
                                          0x00, 0x01, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00 };
        static const uint8_t authtag[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0xe0, 0x4d, 0x90, 0x00, 0x33, 0x87, 0x88, 0xa9,
                                           0x5c, 0x22, 0x56, 0xc3, 0xcf, 0xa3, 0xc1, 0x87 };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0xe2, 0xa2, 0x8f, 0x25, 0x30, 0x0c, 0xe8, 0x16,
                                                        0xdb, 0x42, 0xdb, 0xa9, 0xbc, 0xdc, 0xac, 0x63,
                                                        0xf3, 0x31, 0x7b, 0xb7, 0xd9, 0xce, 0xc7, 0xf8 };
        if (testHeaderAuth(
                header, sizeof(header), authtag, sizeof(authtag), key, ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256))
            return 1;
    }
    {
        static const uint8_t header[]  = { 0x01, 0x80, 0x01, 0x78, 0xd4, 0xe9, 0xf9, 0xde, 0xc5, 0xca, 0x9a,
                                          0x36, 0x27, 0x03, 0x9d, 0xd3, 0x1d, 0xfd, 0xbd, 0x29, 0x00, 0x00,
                                          0x00, 0x01, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00 };
        static const uint8_t authtag[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x98, 0xa1, 0xb5, 0x29, 0xcf, 0x56, 0x8f, 0xdf,
                                           0x67, 0x08, 0x49, 0xd7, 0xa7, 0xe3, 0xa6, 0xcc };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0x4e, 0x8d, 0x8f, 0xc6, 0xbe, 0x87, 0x39, 0x6f,
                                                        0x73, 0x57, 0x61, 0xda, 0x35, 0x93, 0x30, 0xbf,
                                                        0x0f, 0xa9, 0x5e, 0xea, 0x97, 0xa7, 0x19, 0xf0,
                                                        0x42, 0xef, 0x50, 0x95, 0x58, 0x95, 0xd6, 0x5d };
        if (testHeaderAuth(
                header, sizeof(header), authtag, sizeof(authtag), key, ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256))
            return 1;
    }
    {
        static const uint8_t header[]  = { 0x01, 0x80, 0x02, 0x14, 0xb6, 0xaf, 0xf6, 0xd4, 0x6f, 0x51, 0x0d, 0xd4, 0x8e,
                                          0xd1, 0xdc, 0x5b, 0x2f, 0x1d, 0x0f, 0x7e, 0x00, 0x47, 0x00, 0x01, 0x00, 0x15,
                                          0x61, 0x77, 0x73, 0x2d, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2d, 0x70, 0x75,
                                          0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x00, 0x2c, 0x41, 0x6a, 0x35,
                                          0x5a, 0x31, 0x47, 0x6d, 0x5a, 0x72, 0x6f, 0x56, 0x37, 0x52, 0x4f, 0x34, 0x6a,
                                          0x7a, 0x45, 0x6b, 0x57, 0x50, 0x39, 0x4a, 0x7a, 0x4e, 0x37, 0x4c, 0x76, 0x64,
                                          0x58, 0x56, 0x55, 0x63, 0x35, 0x54, 0x55, 0x6b, 0x35, 0x71, 0x4c, 0x76, 0x62,
                                          0x74, 0x4a, 0x00, 0x01, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00 };
        static const uint8_t authtag[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0xfe, 0x7c, 0x51, 0xf9, 0x01, 0xe4, 0x91, 0x68,
                                           0xb3, 0x6e, 0xd6, 0xde, 0x3c, 0x01, 0x32, 0x01 };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0x51, 0x31, 0x83, 0xbe, 0xf7, 0xb7, 0x21, 0xaa,
                                                        0x40, 0x01, 0x79, 0xb6, 0x28, 0x9d, 0x6b, 0x49 };
        if (testHeaderAuth(
                header,
                sizeof(header),
                authtag,
                sizeof(authtag),
                key,
                ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256))
            return 1;
    }
    {
        static const uint8_t header[] = {
            0x01, 0x80, 0x03, 0x46, 0x1a, 0xd8, 0x19, 0xb3, 0x23, 0xd7, 0xca, 0x21, 0xcd, 0xbc, 0xb9, 0xcb, 0x58,
            0x5d, 0x23, 0xd8, 0x00, 0x5f, 0x00, 0x01, 0x00, 0x15, 0x61, 0x77, 0x73, 0x2d, 0x63, 0x72, 0x79, 0x70,
            0x74, 0x6f, 0x2d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x00, 0x44, 0x41, 0x39,
            0x76, 0x61, 0x75, 0x45, 0x43, 0x67, 0x47, 0x4f, 0x2b, 0x61, 0x72, 0x4b, 0x57, 0x59, 0x67, 0x52, 0x44,
            0x46, 0x6c, 0x73, 0x62, 0x6c, 0x39, 0x49, 0x4f, 0x30, 0x35, 0x67, 0x6f, 0x34, 0x4a, 0x45, 0x51, 0x75,
            0x67, 0x62, 0x5a, 0x79, 0x4b, 0x69, 0x38, 0x73, 0x79, 0x69, 0x33, 0x65, 0x36, 0x46, 0x37, 0x42, 0x61,
            0x67, 0x38, 0x73, 0x47, 0x2f, 0x74, 0x42, 0x56, 0x46, 0x32, 0x50, 0x41, 0x51, 0x3d, 0x3d, 0x00, 0x01,
            0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00
        };
        static const uint8_t authtag[]              = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x09, 0xe1, 0x8f, 0x93, 0xa5, 0x68, 0xc9, 0x94,
                                           0x1c, 0x33, 0x43, 0x28, 0x90, 0x52, 0x30, 0x09 };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0x10, 0xa3, 0x3d, 0xbb, 0x6b, 0xa7, 0xfa, 0xb8,
                                                        0xd1, 0x7c, 0xee, 0xd1, 0x1c, 0xf5, 0xc7, 0xa9,
                                                        0x6d, 0x02, 0x43, 0xb2, 0x64, 0x84, 0xc0, 0x62 };
        if (testHeaderAuth(
                header,
                sizeof(header),
                authtag,
                sizeof(authtag),
                key,
                ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384))
            return 1;
    }
    {
        static const uint8_t header[] = {
            0x01, 0x80, 0x03, 0x78, 0x84, 0xae, 0x67, 0x58, 0x7a, 0x6e, 0xe7, 0xdc, 0xb7, 0xd3, 0x39, 0xe8, 0x4d,
            0x0b, 0xc2, 0xef, 0x00, 0x5f, 0x00, 0x01, 0x00, 0x15, 0x61, 0x77, 0x73, 0x2d, 0x63, 0x72, 0x79, 0x70,
            0x74, 0x6f, 0x2d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x00, 0x44, 0x41, 0x35,
            0x34, 0x74, 0x6e, 0x55, 0x76, 0x39, 0x4c, 0x42, 0x37, 0x4a, 0x44, 0x54, 0x76, 0x47, 0x36, 0x2f, 0x35,
            0x4c, 0x5a, 0x36, 0x70, 0x65, 0x53, 0x6a, 0x46, 0x77, 0x77, 0x79, 0x62, 0x68, 0x45, 0x6f, 0x4b, 0x6f,
            0x48, 0x30, 0x7a, 0x61, 0x79, 0x48, 0x57, 0x64, 0x64, 0x77, 0x6b, 0x36, 0x34, 0x62, 0x31, 0x76, 0x6a,
            0x67, 0x5a, 0x71, 0x4b, 0x38, 0x71, 0x59, 0x54, 0x79, 0x41, 0x44, 0x50, 0x41, 0x3d, 0x3d, 0x00, 0x01,
            0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x10, 0x00
        };
        static const uint8_t authtag[]              = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0xb5, 0xc1, 0x2a, 0x88, 0xb2, 0xc3, 0xf7, 0x54,
                                           0x8f, 0xb6, 0xa9, 0x35, 0x67, 0xd3, 0xd9, 0xde };
        static const uint8_t key[MAX_DATA_KEY_SIZE] = { 0xe3, 0xce, 0xce, 0x1b, 0x53, 0xe2, 0x4f, 0x3b,
                                                        0xcc, 0xa3, 0xc4, 0xb0, 0x1d, 0x77, 0x2d, 0x52,
                                                        0x51, 0x9a, 0x9f, 0x36, 0xa3, 0x58, 0x0b, 0x27,
                                                        0x3d, 0x10, 0xdd, 0xc8, 0xa4, 0xda, 0x2f, 0x63 };
        if (testHeaderAuth(
                header,
                sizeof(header),
                authtag,
                sizeof(authtag),
                key,
                ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384))
            return 1;
    }
    {
        struct aws_byte_buf header = easy_b64_decode(
            "AgR4TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXkAAAABAAxQcm92aWRlck5hbWUAGUtl"
            "eUlkAAAAgAAAAAz45sc3cDvJZ7D4P3sAMKE7d/w8ziQt2C0qHsy1Qu2E2q92eIGE/kLnF/Y003HK"
            "vTxx7xv2Zv83YuOdwHML5QIAABAAF88I9zPbUQSfOlzLXv+uIY2+m/E6j2PMsbgeHVH/L0w=");
        struct aws_byte_buf content_key = easy_b64_decode("+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0=");
        static const uint8_t authtag[]  = { 0x0b, 0xa9, 0x09, 0x58, 0xfb, 0x90, 0x8b, 0xd3,
                                           0x3d, 0xf1, 0x9c, 0xd3, 0x8c, 0x21, 0x96, 0x9e };

        if (testHeaderAuth(
                header.buffer,
                header.len,
                authtag,
                sizeof(authtag),
                content_key.buffer,
                ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY))
            return 1;

        aws_byte_buf_clean_up(&content_key);
        aws_byte_buf_clean_up(&header);
    }
    return 0;
}

static int test_random() {
    // There's not too much we can test for a RNG, but at least do a simple sanity test...
    uint8_t buf1[16]           = { 0 };
    uint8_t buf2[sizeof(buf1)] = { 0 };

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_genrandom(buf1, sizeof(buf1)));
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_genrandom(buf2, sizeof(buf2)));

    TEST_ASSERT_INT_EQ(0, !memcmp(buf1, buf2, sizeof(buf1)));

    return 0;
}

static const enum aws_cryptosdk_alg_id known_algorithms[] = { ALG_AES128_GCM_IV12_TAG16_NO_KDF,
                                                              ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
                                                              ALG_AES192_GCM_IV12_TAG16_NO_KDF,
                                                              ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256,
                                                              ALG_AES256_GCM_IV12_TAG16_NO_KDF,
                                                              ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
                                                              ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
                                                              ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                                                              ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                                                              ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY,
                                                              ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 };

static const size_t test_sizes[] = {
    1,
    2,
    3,
    5,
    15,
    16,
    17,
    1023,
    1024,
    1025,
    65535,
    65536,
    65537,
#ifndef REDUCE_TEST_ITERATIONS
    1024 * 1024 * 64 - 1,
    1024 * 1024 * 64,
    1024 * 1024 * 64 + 1,
#endif
    // Make sure we don't end the list with a conditonal entry, to avoid problems with trailing commas
    42
};

static int test_encrypt_body() {
    uint32_t seqno              = 0xDEADBEEF;
    struct aws_allocator *alloc = aws_default_allocator();
    struct content_key key;

    aws_cryptosdk_genrandom(key.keybuf, sizeof(key.keybuf));

    for (size_t size_idx = 0; size_idx < sizeof(test_sizes) / sizeof(test_sizes[0]); size_idx++) {
        struct aws_byte_buf pt_buf = { 0 }, ct_buf = { 0 }, decrypt_buf = { 0 };
        size_t buf_size = test_sizes[size_idx];

        if (aws_byte_buf_init(&pt_buf, alloc, buf_size)) abort();
        if (aws_byte_buf_init(&ct_buf, alloc, buf_size)) abort();
        if (aws_byte_buf_init(&decrypt_buf, alloc, buf_size)) abort();
        pt_buf.len      = pt_buf.capacity;
        ct_buf.len      = ct_buf.capacity;
        decrypt_buf.len = decrypt_buf.capacity;

        TEST_ASSERT_INT_EQ(pt_buf.len, buf_size);
        TEST_ASSERT_INT_EQ(ct_buf.len, buf_size);
        TEST_ASSERT_INT_EQ(decrypt_buf.len, buf_size);

        aws_cryptosdk_genrandom(pt_buf.buffer, pt_buf.len);

        for (size_t i = 0; i < sizeof(known_algorithms) / sizeof(known_algorithms[0]); i++) {
            enum aws_cryptosdk_alg_id alg_id               = known_algorithms[i];
            const struct aws_cryptosdk_alg_properties *alg = aws_cryptosdk_alg_props(alg_id);
            size_t message_id_len                          = aws_cryptosdk_private_algorithm_message_id_len(alg);

            // SINGLE, FRAME, FINAL
            for (int frame_type = 0; frame_type <= FRAME_TYPE_FINAL; frame_type++) {
                uint8_t iv[12];
                uint8_t tag[16];
                struct aws_byte_buf msg_id;

                TEST_ASSERT_SUCCESS(aws_byte_buf_init(&msg_id, aws_default_allocator(), message_id_len));
                msg_id.len = msg_id.capacity;

                memset(iv, 0xFF, sizeof(iv));
                memset(tag, 0xFF, sizeof(tag));

                aws_byte_buf_secure_zero(&ct_buf);
                ct_buf.len = 0;
                aws_cryptosdk_genrandom(msg_id.buffer, msg_id.len);

                struct aws_byte_cursor pt_cursor = aws_byte_cursor_from_buf(&pt_buf);

                TEST_ASSERT_SUCCESS(
                    aws_cryptosdk_encrypt_body(alg, &ct_buf, &pt_cursor, &msg_id, seqno, iv, &key, tag, frame_type));

                struct aws_byte_cursor ct_cursor = aws_byte_cursor_from_buf(&ct_buf);
                decrypt_buf.len                  = 0;

                TEST_ASSERT_SUCCESS(aws_cryptosdk_decrypt_body(
                    alg, &decrypt_buf, &ct_cursor, &msg_id, seqno, iv, &key, tag, frame_type));

                TEST_ASSERT_INT_EQ(0, memcmp(decrypt_buf.buffer, pt_buf.buffer, pt_buf.len));

                uint8_t expected_iv[256];
                memset(expected_iv, 0, alg->iv_len);
                expected_iv[alg->iv_len - 4] = 0xDE;
                expected_iv[alg->iv_len - 3] = 0xAD;
                expected_iv[alg->iv_len - 2] = 0xBE;
                expected_iv[alg->iv_len - 1] = 0xEF;

                TEST_ASSERT_INT_EQ(0, memcmp(expected_iv, iv, alg->iv_len));

                aws_byte_buf_clean_up(&msg_id);
            }
        }

        aws_byte_buf_clean_up(&pt_buf);
        aws_byte_buf_clean_up(&ct_buf);
        aws_byte_buf_clean_up(&decrypt_buf);
    }

    return 0;
}

static int test_sign_header() {
    struct aws_allocator *alloc = aws_default_allocator();
    struct content_key key;

    aws_cryptosdk_genrandom(key.keybuf, sizeof(key.keybuf));

    for (size_t size_idx = 0; size_idx < sizeof(test_sizes) / sizeof(test_sizes[0]); size_idx++) {
        struct aws_byte_buf header_buf = { 0 };
        size_t buf_size                = test_sizes[size_idx];

        if (aws_byte_buf_init(&header_buf, alloc, buf_size)) abort();

        aws_cryptosdk_genrandom(header_buf.buffer, header_buf.len);

        for (size_t i = 0; i < sizeof(known_algorithms) / sizeof(known_algorithms[0]); i++) {
            enum aws_cryptosdk_alg_id alg_id               = known_algorithms[i];
            const struct aws_cryptosdk_alg_properties *alg = aws_cryptosdk_alg_props(alg_id);

            size_t auth_tag_size;
            if (alg->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_1_0) {
                auth_tag_size = alg->iv_len + alg->tag_len;
            } else {
                auth_tag_size = alg->tag_len;
            }

            uint8_t auth_tag[256];
            memset(auth_tag, 0xFF, auth_tag_size);

            struct aws_byte_buf auth_buf = aws_byte_buf_from_array(auth_tag, auth_tag_size);

            TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_sign_header(alg, &key, &auth_buf, &header_buf));

            TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_verify_header(alg, &key, &auth_buf, &header_buf));

            if (alg->msg_format_version == AWS_CRYPTOSDK_HEADER_VERSION_1_0) {
                uint8_t expected_iv[256];
                memset(expected_iv, 0, alg->iv_len);
                TEST_ASSERT_INT_EQ(0, memcmp(expected_iv, auth_tag, alg->iv_len));
            }
        }

        aws_byte_buf_clean_up(&header_buf);
    }

    return 0;
}

static int test_digest_sha512() {
    struct aws_allocator *allocator = aws_default_allocator();
    struct aws_cryptosdk_md_context *context;
    uint8_t buf[AWS_CRYPTOSDK_MD_MAX_SIZE];
    uint8_t expected[] = { /* SHA-512 of "foobarbaz" */
                           0xcb, 0x37, 0x7c, 0x10, 0xb0, 0xf5, 0xa6, 0x2c, 0x80, 0x36, 0x25, 0xa7, 0x99,
                           0xd9, 0xe9, 0x08, 0xbe, 0x45, 0xe7, 0x67, 0xf5, 0xd1, 0x47, 0xd4, 0x74, 0x49,
                           0x07, 0xcb, 0x05, 0x59, 0x7a, 0xa4, 0xed, 0xd3, 0x29, 0xa0, 0xaf, 0x14, 0x7a,
                           0xdd, 0x0c, 0xf4, 0x18, 0x1e, 0xd3, 0x28, 0xfa, 0x1e, 0x79, 0x94, 0x26, 0x58,
                           0x26, 0xb3, 0xed, 0x3d, 0x7e, 0xf6, 0xf0, 0x67, 0xca, 0x99, 0x18, 0x5a
    };
    size_t md_len;

    TEST_ASSERT_INT_EQ(64, aws_cryptosdk_md_size(AWS_CRYPTOSDK_MD_SHA512));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_md_init(allocator, &context, AWS_CRYPTOSDK_MD_SHA512));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_md_update(context, "foo", 3));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_md_update(context, "barbaz", 6));
    TEST_ASSERT_SUCCESS(aws_cryptosdk_md_finish(context, buf, &md_len));

    TEST_ASSERT_INT_EQ(md_len, sizeof(expected));
    TEST_ASSERT_INT_EQ(0, memcmp(expected, buf, md_len));

    /* test abort path as well */
    TEST_ASSERT_SUCCESS(aws_cryptosdk_md_init(allocator, &context, AWS_CRYPTOSDK_MD_SHA512));
    aws_cryptosdk_md_abort(context);

    return 0;
}

struct test_case cipher_test_cases[] = { { "cipher", "test_kdf", test_kdf },
                                         { "cipher", "test_decrypt_frame_aad", test_decrypt_frame_aad },
                                         { "cipher", "test_decrypt_frame_all_algos", test_decrypt_frame_all_algos },
                                         { "cipher", "test_verify_header", test_verify_header },
                                         { "cipher", "test_random", test_random },
                                         { "cipher", "test_encrypt_body", test_encrypt_body },
                                         { "cipher", "test_sign_header", test_sign_header },
                                         { "cipher", "test_digest_sha512", test_digest_sha512 },
                                         { NULL } };
