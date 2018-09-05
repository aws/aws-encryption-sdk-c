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

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/cipher.h>
#include <aws/cryptosdk/private/cipher.h>

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
    struct aws_byte_buf *pubkey,
    struct aws_byte_buf *sig,
    const struct aws_byte_buf *data
) {
    struct aws_cryptosdk_signctx *ctx;

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), pubkey, props)
    );

    TEST_ASSERT_ADDR_NOT_NULL(ctx);

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_update(ctx, data)
    );

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), sig)
    );

    return 0;
}

static int check_signature(
    const struct aws_cryptosdk_alg_properties *props,
    bool expect_valid,
    struct aws_byte_buf *pubkey,
    struct aws_byte_buf *sig,
    const struct aws_byte_buf *data
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

    TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, data));

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
        struct aws_byte_buf pub_key_buf, sig_buf;
        struct aws_byte_buf data = aws_byte_buf_from_c_str("Hello, world!");

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_buf, &sig_buf, &data));
        TEST_ASSERT_SUCCESS(check_signature(props, true, &pub_key_buf, &sig_buf, &data));

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int t_signature_length() {
    FOREACH_ALGORITHM(props) {
        size_t len = props->signature_len;
        struct aws_byte_buf pub_key_buf, sig_buf;
        struct aws_byte_buf data = aws_byte_buf_from_c_str("Hello, world!");

        /*
         * Normally, EC signatures have slightly non-deterministic length in DER encoding, make sure that
         * we've successfully made them deterministic
         */
        for (int i = 0; i < 256; i++) {
            TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_buf, &sig_buf, &data));
            TEST_ASSERT_INT_EQ(sig_buf.len, len);
            TEST_ASSERT_SUCCESS(check_signature(props, true, &pub_key_buf, &sig_buf, &data));

            aws_byte_buf_clean_up(&pub_key_buf);
            aws_byte_buf_clean_up(&sig_buf);
        }
    }

    return 0;
}

static int t_bad_signatures() {
    FOREACH_ALGORITHM(props) {
        struct aws_byte_buf pub_key_buf, sig_buf;
        struct aws_byte_buf data = aws_byte_buf_from_c_str("Hello, world!");

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_buf, &sig_buf, &data));

        for (size_t i = 0; i < sig_buf.len * 8; i++) {
            sig_buf.buffer[i/8] ^= (1 << (i % 8));
            if (check_signature(props, false, &pub_key_buf, &sig_buf, &data)) {
                sig_buf.buffer[i/8] ^= (1 << (i % 8));
                fprintf(stderr, "Unexpected success for cipher suite %s at corrupted bit index %zu (byte 0x%04zx mask %02x)\n",
                    props->alg_name, i, i / 8, 1 << (1 % 8)
                );
                hexdump(stderr, sig_buf.buffer, sig_buf.len);
                return 1;
            }
            sig_buf.buffer[i/8] ^= (1 << (i % 8));
        }

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int t_key_mismatch() {
    FOREACH_ALGORITHM(props) {
        struct aws_byte_buf pub_key_1, pub_key_2, sig_buf;
        struct aws_byte_buf data = aws_byte_buf_from_c_str("Hello, world!");

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_1, &sig_buf, &data));
        aws_byte_buf_clean_up(&sig_buf);

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_2, &sig_buf, &data));
        TEST_ASSERT_SUCCESS(check_signature(props, false, &pub_key_1, &sig_buf, &data));

        aws_byte_buf_clean_up(&pub_key_1);
        aws_byte_buf_clean_up(&pub_key_2);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int t_corrupt_key() {
    FOREACH_ALGORITHM(props) {
        struct aws_byte_buf pub_key_buf, sig_buf;
        struct aws_byte_buf data = aws_byte_buf_from_c_str("Hello, world!");

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_buf, &sig_buf, &data));

        for (size_t i = 0; i < pub_key_buf.len * 8; i++) {
            /* The base64 decoding logic ignores nonzero padding bits, so skip the last byte before an = */
            if (i < (pub_key_buf.len - 1) * 8 && pub_key_buf.buffer[i / 8 + 1] == '=') {
                continue;
            }

            pub_key_buf.buffer[i / 8] ^= 1 << (i % 8);

            if (check_signature(props, false, &pub_key_buf, &sig_buf, &data)) {
                pub_key_buf.buffer[i / 8] ^= 1 << (i % 8);
                fprintf(stderr, "Unexpected success for cipher suite %s at corrupted key bit index %zu (byte 0x%04zx mask %02x)\n",
                    props->alg_name, i, i/8, 1 << (i % 8)
                );

                fprintf(stderr, "Key:\n");
                hexdump(stderr, pub_key_buf.buffer, pub_key_buf.len);

                fprintf(stderr, "Corrupt key:\n");
                pub_key_buf.buffer[i / 8] ^= 1 << (i % 8);
                hexdump(stderr, pub_key_buf.buffer, pub_key_buf.len);

                fprintf(stderr, "Signature:\n");
                hexdump(stderr, sig_buf.buffer, sig_buf.len);

                return 1;
            }

            pub_key_buf.buffer[i / 8] ^= 1 << (i % 8);
        }

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int t_wrong_data() {
    FOREACH_ALGORITHM(props) {
        struct aws_byte_buf pub_key_buf, sig_buf;
        struct aws_byte_buf data = aws_byte_buf_from_c_str("Hello, world!");
        struct aws_byte_buf bad_data = aws_byte_buf_from_c_str("Hello, world?");

        TEST_ASSERT_SUCCESS(sign_message(props, &pub_key_buf, &sig_buf, &data));
        TEST_ASSERT_SUCCESS(check_signature(props, false, &pub_key_buf, &sig_buf, &bad_data));

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int t_partial_update() {
    FOREACH_ALGORITHM(props) {
        struct aws_byte_buf pub_key_buf, sig_buf;
        struct aws_byte_buf d_empty = aws_byte_buf_from_c_str("");
        struct aws_byte_buf d_1_1 = aws_byte_buf_from_c_str("Hello,");
        struct aws_byte_buf d_1_2 = aws_byte_buf_from_c_str(" world!");
        struct aws_byte_buf d_2_1 = aws_byte_buf_from_c_str("Hello, world");
        struct aws_byte_buf d_2_2 = aws_byte_buf_from_c_str("!");

        struct aws_cryptosdk_signctx *ctx;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), &pub_key_buf, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_1_1));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_1_2));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), &sig_buf));

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_start(&ctx, aws_default_allocator(), &pub_key_buf, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_2_1));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_2_2));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_finish(ctx, &sig_buf));

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int t_serialize_privkey() {
    FOREACH_ALGORITHM(props) {
        struct aws_byte_buf pub_key_buf, pub_key_buf_2, priv_key_buf, sig_buf;
        struct aws_cryptosdk_signctx *ctx;
        struct aws_byte_buf data = aws_byte_buf_from_c_str("Hello, world!");

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), &pub_key_buf, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_get_privkey(ctx, aws_default_allocator(), &priv_key_buf));
        aws_cryptosdk_sig_abort(ctx);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start(&ctx, aws_default_allocator(), &pub_key_buf_2, props, &priv_key_buf));
        TEST_ASSERT(aws_byte_buf_eq(&pub_key_buf, &pub_key_buf_2));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &data));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), &sig_buf));

        TEST_ASSERT_SUCCESS(check_signature(props, true, &pub_key_buf, &sig_buf, &data));

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&pub_key_buf_2);
        aws_byte_buf_clean_up_secure(&priv_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int t_empty_signature() {
    FOREACH_ALGORITHM(props) {
        struct aws_byte_buf pub_key_buf, sig_buf;
        struct aws_byte_buf d_empty = aws_byte_buf_from_c_str("");

        struct aws_cryptosdk_signctx *ctx;

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start_keygen(&ctx, aws_default_allocator(), &pub_key_buf, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(ctx, aws_default_allocator(), &sig_buf));

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_start(&ctx, aws_default_allocator(), &pub_key_buf, props));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_finish(ctx, &sig_buf));

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

    return 0;
}

static int testVector(const char *algName, enum aws_cryptosdk_alg_id alg_id, const char *pubkey, const char *sig) {
    struct aws_byte_buf tbs = aws_byte_buf_from_c_str("Hello, world!");
    struct aws_byte_buf pubkey_buf = aws_byte_buf_from_c_str(pubkey);
    struct aws_byte_buf sig_buf = aws_byte_buf_from_c_str(sig);

    TEST_ASSERT_SUCCESS(check_signature(
        aws_cryptosdk_alg_props(alg_id),
        true,
        &pubkey_buf,
        &sig_buf,
        &tbs
    ));

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
    struct aws_byte_buf tbs = aws_byte_buf_from_c_str("Hello, world!");
    // There is an extra 0 byte appended to this public key (prior to base64 encoding)
    struct aws_byte_buf pubkey_buf = aws_byte_buf_from_c_str("A7dANHB8VOVfkdxBqZhXmD5xnRCbN8+tYjmq7L4MMa0yAA==");
    struct aws_byte_buf sig_buf = aws_byte_buf_from_c_str("MEYCIQDIRrHUpsJDWsguDyT/CY0+IGL7f0W8LdGz2kqXvgfSJwIhAKoy0JFwexw2aqRaI4+TSrC+CKBGHEgSvP/vcQaQDyDR");

    TEST_ASSERT_SUCCESS(check_signature(
        aws_cryptosdk_alg_props(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256),
        false, &pubkey_buf, &sig_buf, &tbs
    ));

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
