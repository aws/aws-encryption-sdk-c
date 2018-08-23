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
        aws_cryptosdk_sig_keygen(aws_default_allocator(), &ctx, props, pubkey)
    );

    TEST_ASSERT_ADDR_NOT_NULL(ctx);

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_update(ctx, data)
    );

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_sig_sign_finish(aws_default_allocator(), ctx, sig)
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
            aws_cryptosdk_sig_verify_start(aws_default_allocator(), &ctx, props, pubkey)
        );
    } else {
        int rv = aws_cryptosdk_sig_verify_start(aws_default_allocator(), &ctx, props, pubkey);

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

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_keygen(aws_default_allocator(), &ctx, props, &pub_key_buf));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_1_1));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_1_2));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(aws_default_allocator(), ctx, &sig_buf));

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_start(aws_default_allocator(), &ctx, props, &pub_key_buf));
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

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_keygen(aws_default_allocator(), &ctx, props, &pub_key_buf));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_get_privkey(aws_default_allocator(), ctx, &priv_key_buf));
        aws_cryptosdk_sig_abort(ctx);

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_start(aws_default_allocator(), &ctx, &pub_key_buf_2, props, &priv_key_buf));
        TEST_ASSERT(aws_byte_buf_eq(&pub_key_buf, &pub_key_buf_2));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &data));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(aws_default_allocator(), ctx, &sig_buf));

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

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_keygen(aws_default_allocator(), &ctx, props, &pub_key_buf));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_sign_finish(aws_default_allocator(), ctx, &sig_buf));

        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_start(aws_default_allocator(), &ctx, props, &pub_key_buf));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_update(ctx, &d_empty));
        TEST_ASSERT_SUCCESS(aws_cryptosdk_sig_verify_finish(ctx, &sig_buf));

        aws_byte_buf_clean_up(&pub_key_buf);
        aws_byte_buf_clean_up(&sig_buf);
    }

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
    { NULL }
};
