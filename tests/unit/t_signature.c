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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "testutil.h"

#include <aws/common/encoding.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/cipher.h>

static struct aws_byte_cursor cursor_from_c_string(const char *str) {
    struct aws_byte_buf buf = aws_byte_buf_from_c_str(str);
    return aws_byte_cursor_from_buf(&buf);
}

static const char test_data[] = "Hello, world!";
static const struct aws_byte_cursor test_cursor = { .ptr = (uint8_t *)test_data, .len = sizeof(test_data) - 1 };

static const enum aws_cryptosdk_alg_id SIG_ALGORITHMS[] = {
    AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256,
    AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
    AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384
};

#define FOREACH_ALGORITHM(props) \
    const struct aws_cryptosdk_alg_properties *props; \
    for (const enum aws_cryptosdk_alg_id *p_alg_id = SIG_ALGORITHMS; \
         p_alg_id != (const void *)((const uint8_t *)SIG_ALGORITHMS + sizeof(SIG_ALGORITHMS)) \
            && (props = aws_cryptosdk_alg_props(*p_alg_id)); p_alg_id++)


static int sign_message(
    const struct aws_cryptosdk_alg_properties *props,
    struct aws_string **pubkey,
    struct aws_string **sig,
    const struct aws_byte_cursor *data
) {
    struct aws_cryptosdk_signctx *ctx;

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), pubkey, props)
    );

    TEST_ASSERT_ADDR_NOT_NULL(ctx);

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_update(ctx, *data)
    );

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), sig)
    );

    return 0;
}

static int check_signature(
    const struct aws_cryptosdk_alg_properties *props,
    bool expect_valid,
    const struct aws_string *pubkey,
    const struct aws_string *sig,
    const struct aws_byte_cursor *data
) {
    struct aws_cryptosdk_signctx *ctx;

    if (expect_valid) {
        TEST_ASSERT_SUCCESS(
            aws_cryptosdk_sig_verify_start(&ctx, aws_default_allocator(), pubkey, props)
        );
    } else {
        int rv = aws_cryptosdk_sig_verify_start(&ctx, aws_default_allocator(), pubkey, props);

        if (rv != 0) {
            TEST_ASSERT_INT_EQ(aws_last_error(), AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT);
            return 0;
        }
    }

    TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, *data));

    if (expect_valid) {
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_finish(ctx, sig));
    } else {
        TEST_ASSERT_ERROR(AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT,
            aws_cryptosdk_sig_verify_finish(ctx, sig)
        );
    }

    return 0;
}

static int t_basic_signature_sign_verify() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key, *sig;

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key, &sig, &test_cursor));
        TEST_ASSERT_SUCCESS(check_signature(props, true, pub_key, sig, &test_cursor));

        aws_string_destroy(pub_key);
        aws_string_destroy(sig);
    }

    return 0;
}

static int t_signature_length() {
    FOREACH_ALGORITHM(props) {
        size_t len = props->signature_len;
        struct aws_string *pub_key, *sig;
#ifndef REDUCE_TEST_ITERATIONS
        const int iterations = 256;
#else
        const int iterations = 8;
#endif

        /*
         * Normally, EC signatures have slightly non-deterministic length in DER encoding, make sure that
         * we've successfully made them deterministic
         */
        for (int i = 0; i < iterations; i++) {
            TEST_ASSERT_SUCCESS(sign_message(props, &pub_key, &sig, &test_cursor));
            TEST_ASSERT_INT_EQ(sig->len, len);
            TEST_ASSERT_SUCCESS(check_signature(props, true, pub_key, sig, &test_cursor));

            aws_string_destroy(pub_key);
            aws_string_destroy(sig);
        }
    }

    return 0;
}

static int t_bad_signatures() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key, *sig;

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key, &sig, &test_cursor));
        uint8_t *buffer = (uint8_t *)aws_string_bytes(sig);

#ifndef REDUCE_TEST_ITERATIONS
        const size_t increment = 1;
#else
        const size_t increment = 8;
#endif

        for (size_t i = 0; i < sig->len * 8; i += increment) {
            if (i < (sig->len - 1) * 8 && buffer[i/8 + 1] == '=') {
                /* The last few bits before the "=" padding don't affect the base64-decoded signature. */
                break;
            }
            buffer[i/8] ^= (1 << (i % 8));
            if (check_signature(props, false, pub_key, sig, &test_cursor)) {
                buffer[i/8] ^= (1 << (i % 8));
                fprintf(stderr, "Unexpected success for cipher suite %s at corrupted bit index %zu (byte 0x%04zx mask %02x)\n",
                    props->alg_name, i, i / 8, 1 << (1 % 8)
                );
                hexdump(stderr, buffer, sig->len);
                return 1;
            }
            buffer[i/8] ^= (1 << (i % 8));
        }

        aws_string_destroy(pub_key);
        aws_string_destroy(sig);
    }

    return 0;
}

static int t_key_mismatch() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key_1, *pub_key_2, *sig;

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_1, &sig, &test_cursor));
        aws_string_destroy(sig);

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_2, &sig, &test_cursor));
        TEST_ASSERT_SUCCESS(check_signature(props, false, pub_key_1, sig, &test_cursor));

        aws_string_destroy(pub_key_1);
        aws_string_destroy(pub_key_2);
        aws_string_destroy(sig);
    }

    return 0;
}

static int t_corrupt_key() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key, *sig;

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key, &sig, &test_cursor));

        uint8_t *buffer = (uint8_t *)aws_string_bytes(pub_key);

#ifndef REDUCE_TEST_ITERATIONS
        const size_t increment = 1;
#else
        const size_t increment = 8;
#endif

        for (size_t i = 0; i < pub_key->len * 8; i += increment) {
            /* The base64 decoding logic ignores nonzero padding bits, so skip the last byte before an = */
            if (i < (pub_key->len - 1) * 8 && buffer[i / 8 + 1] == '=') {
                continue;
            }

            buffer[i / 8] ^= 1 << (i % 8);

            if (check_signature(props, false, pub_key, sig, &test_cursor)) {
                buffer[i / 8] ^= 1 << (i % 8);
                fprintf(stderr, "Unexpected success for cipher suite %s at corrupted key bit index %zu (byte 0x%04zx mask %02x)\n",
                    props->alg_name, i, i/8, 1 << (i % 8)
                );

                buffer[i / 8] ^= 1 << (i % 8);
                check_signature(props, false, pub_key, sig, &test_cursor);
                buffer[i / 8] ^= 1 << (i % 8);
                check_signature(props, true, pub_key, sig, &test_cursor);

                fprintf(stderr, "Key:\n");
                hexdump(stderr, aws_string_bytes(pub_key), pub_key->len);

                fprintf(stderr, "Corrupt key:\n");
                buffer[i / 8] ^= 1 << (i % 8);
                hexdump(stderr, aws_string_bytes(pub_key), pub_key->len);

                check_signature(props, false, pub_key, sig, &test_cursor) ;

                fprintf(stderr, "Signature:\n");
                hexdump(stderr, aws_string_bytes(sig), sig->len);

                return 1;
            }

            buffer[i / 8] ^= 1 << (i % 8);
        }

        aws_string_destroy(pub_key);
        aws_string_destroy(sig);
    }

    return 0;
}

static int t_wrong_data() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key, *sig;
        struct aws_byte_buf bad_data = aws_byte_buf_from_c_str("Hello, world?");
        struct aws_byte_cursor bad_cursor = aws_byte_cursor_from_buf(&bad_data);

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key, &sig, &test_cursor));
        TEST_ASSERT_SUCCESS(check_signature(props, false, pub_key, sig, &bad_cursor));

        aws_string_destroy(pub_key);
        aws_string_destroy(sig);
    }

    return 0;
}

static int t_partial_update() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key, *sig;
        struct aws_byte_cursor d_empty = cursor_from_c_string("");
        struct aws_byte_cursor d_1_1 = cursor_from_c_string("Hello,");
        struct aws_byte_cursor d_1_2 = cursor_from_c_string(" world!");
        struct aws_byte_cursor d_2_1 = cursor_from_c_string("Hello, world");
        struct aws_byte_cursor d_2_2 = cursor_from_c_string("!");

        struct aws_cryptosdk_signctx *ctx;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), &pub_key, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_1_1));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_1_2));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), &sig));

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_start(&ctx, aws_default_allocator(), pub_key, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_2_1));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_2_2));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_finish(ctx, sig));

        aws_string_destroy(pub_key);
        aws_string_destroy(sig);
    }

    return 0;
}

static int t_serialize_privkey() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key, *pub_key_2, *priv_key, *sig;
        struct aws_cryptosdk_signctx *ctx;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), &pub_key, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_get_privkey(ctx, aws_default_allocator(), &priv_key));
        aws_cryptosdk_sig_abort(ctx);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start(&ctx, aws_default_allocator(), &pub_key_2, props, priv_key));
        TEST_ASSERT(aws_string_compare(pub_key, pub_key_2) == 0);
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, test_cursor));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), &sig));

        TEST_ASSERT_SUCCESS(check_signature(props, true, pub_key, sig, &test_cursor));

        aws_string_destroy(pub_key);
        aws_string_destroy(pub_key_2);
        aws_string_destroy(sig);
        aws_string_destroy_secure(priv_key);
    }

    return 0;
}

static int t_empty_signature() {
    FOREACH_ALGORITHM(props) {
        struct aws_string *pub_key, *sig;
        struct aws_byte_cursor d_empty = aws_byte_cursor_from_array("", 0);

        struct aws_cryptosdk_signctx *ctx;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), &pub_key, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), &sig));

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_start(&ctx, aws_default_allocator(), pub_key, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_finish(ctx, sig));

        aws_string_destroy(pub_key);
        aws_string_destroy(sig);
    }

    return 0;
}

static int testVector(const char *algName, enum aws_cryptosdk_alg_id alg_id, const char *pubkey_s, const char *sig_s) {
    uint8_t tmparr[512];
    struct aws_byte_buf tmpbuf = aws_byte_buf_from_array(tmparr, sizeof(tmparr));
    struct aws_byte_buf sigraw = aws_byte_buf_from_c_str(sig_s);

    TEST_ASSERT_SUCCESS(aws_base64_decode(&sigraw, &tmpbuf));

    struct aws_string *pubkey = aws_string_new_from_c_str(aws_default_allocator(), pubkey_s);
    struct aws_string *sig = aws_string_new_from_array(aws_default_allocator(), tmpbuf.buffer, tmpbuf.len);

    if (check_signature(
        aws_cryptosdk_alg_props(alg_id),
        true,
        pubkey, 
        sig,
        &test_cursor
    )) {
        fprintf(stderr, "\nSignature check failed for test vector %s\n", algName);
        return 1;
    }

    aws_string_destroy(pubkey);
    aws_string_destroy(sig);

    return 0;
}

static int t_test_vectors() {
    if (testVector("ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256", AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256,
        "AsPvc4yRhLSzEbcIMQFT5aAG8naQl8y/0IdFNn6fvVtL",
        "MEUCIQDcsouTt0S3LyrtSb2m/zNHaq1ftxBrsvtQ/coYVW3gEwIgYMkVF/0VR7Ld6daZBRIv2ElRvTIEtRFcg5vNYT3yH38=")
    ) {
        return 1;
    }
    if (testVector("ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
        "AoZ0mPKrKqcCyWlF47FYUrk4as696N4WUmv+54kp58hBiGJ22Fm+g4esiICWcOrgfQ==",
        "MGUCMBR4nYG2FBx1RLAPbCdCueFIPVTzmLvr+8OQktUtwDEEsKYQfwvyWe+Kq75QalfYBAIxALpk21eyDgo5xD7nUr6fxsOCYICBd11nLavbdjrQDlDIKZQXIpNHI+/omcZ/y1NGPw=="
    )) {
        return 1;
    }
    if (testVector("ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384,
        "AoSuBn3WFhsz0A+wDLFIz0u3xC78A6kLqjeXsLtgQC1+o9687i9Xz5v1doJqjBbmQw==",
        "MGYCMQDBx0arx1QluNYOsmZQRrhv2Lc+BDTIbMPDeLHCtZH1ah3VkbYxBBIrr3X4QhJVFSsCMQDbUrtTnKf8+C4aDMiBzMVOLjUlKYc2jxlr245DatQ5HqLBS9inTFNMruUQBF/GEyI="
    )) {
        return 1;
    }

    return 0;
}

static int t_trailing_garbage() {
    // There is an extra 0 byte appended to this public key (prior to base64 encoding)
    AWS_STATIC_STRING_FROM_LITERAL(pubkey, "A7dANHB8VOVfkdxBqZhXmD5xnRCbN8+tYjmq7L4MMa0yAA==");

    const char *sig_s = "MEYCIQDIRrHUpsJDWsguDyT/CY0+IGL7f0W8LdGz2kqXvgfSJwIhAKoy0JFwexw2aqRaI4+TSrC+CKBGHEgSvP/vcQaQDyDR";
    uint8_t tmparr[512];
    struct aws_byte_buf tmpbuf = aws_byte_buf_from_array(tmparr, sizeof(tmparr));
    struct aws_byte_buf sigraw = aws_byte_buf_from_c_str(sig_s);

    TEST_ASSERT_SUCCESS(aws_base64_decode(&sigraw, &tmpbuf));

    struct aws_string *sig = aws_string_new_from_array(aws_default_allocator(), sigraw.buffer, sigraw.len);

    TEST_ASSERT_SUCCESS(check_signature(
        aws_cryptosdk_alg_props(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256),
        false, pubkey, sig, &test_cursor
    ));

    aws_string_destroy(sig);

    return 0;
}

struct test_case signature_test_cases[] = {
    { "signature", "t_basic_signature_sign_verify", t_basic_signature_sign_verify },
    { "signature", "t_signature_length", t_signature_length },
    { "signature", "t_bad_signatures", t_bad_signatures },
    { "signature", "t_key_mismatch", t_key_mismatch },
    { "signature", "t_corrupt_key", t_corrupt_key },
    { "signature", "t_wrong_data", t_wrong_data },
    { "signature", "t_partial_update", t_partial_update },
    { "signature", "t_serialize_privkey", t_serialize_privkey },
    { "signature", "t_empty_signature", t_empty_signature },
    { "signature", "t_test_vectors", t_test_vectors },
    { "signature", "t_trailing_garbage", t_trailing_garbage },
    { NULL }
};
