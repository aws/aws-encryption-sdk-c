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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <aws/common/common.h>
#include <aws/common/error.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/raw_aes_keyring.h>
#include <aws/cryptosdk/session.h>

#include "testutil.h"
#include "zero_keyring.h"

/* Braindead option parser for now */
const char *ciphertext_filename, *plaintext_filename;
bool expect_failure = false;
/* Uses an AES-GCM key (consisting of all zeroes) instead of a fixed zeroes data key */
bool gcm_key = false;

uint8_t *ciphertext, *plaintext;
size_t ct_size, pt_size;

#define unexpected_error()                                         \
    do {                                                           \
        fprintf(                                                   \
            stderr,                                                \
            "Unexpected error return (%d, 0x%04x) at %s:%d: %s\n", \
            aws_last_error(),                                      \
            aws_last_error(),                                      \
            __FILE__,                                              \
            __LINE__,                                              \
            aws_error_str(aws_last_error()));                      \
        return 1;                                                  \
    } while (0)

int test_decrypt() {
    aws_cryptosdk_load_error_strings();

    uint8_t *output_buf = malloc(pt_size);
    if (!output_buf) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    struct aws_allocator *alloc           = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr      = NULL;
    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm         = NULL;

    if (gcm_key) {
        struct aws_string *provName = aws_string_new_from_c_str(aws_default_allocator(), "ProviderName");
        struct aws_string *keyId    = aws_string_new_from_c_str(aws_default_allocator(), "KeyId");
        const uint8_t ZERO_KEY[32]  = { 0 };

        if (!(kr = aws_cryptosdk_raw_aes_keyring_new(
                  aws_default_allocator(), provName, keyId, ZERO_KEY, AWS_CRYPTOSDK_AES256)))
            unexpected_error();

        aws_string_destroy(provName);
        aws_string_destroy(keyId);
    } else {
        if (!(kr = aws_cryptosdk_zero_keyring_new(alloc))) unexpected_error();
    }
    if (!(cmm = aws_cryptosdk_default_cmm_new(alloc, kr))) unexpected_error();
    if (!(session = aws_cryptosdk_session_new_from_cmm_2(alloc, AWS_CRYPTOSDK_DECRYPT, cmm))) unexpected_error();
    aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT);

    uint8_t *outp      = output_buf;
    const uint8_t *inp = ciphertext;

    size_t outsz        = pt_size;
    size_t insz         = ct_size;
    size_t out_produced = 0xDEADBEEF;
    size_t in_consumed  = 0xABCD0123;

    int rv = aws_cryptosdk_session_process(session, outp, outsz, &out_produced, inp, insz, &in_consumed);

    if (expect_failure) {
        if (rv != AWS_OP_ERR) {
            fprintf(stderr, "unexpected success\n");
            return 1;
        }
        if (aws_last_error() != AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT) {
            unexpected_error();
        }
    } else {
        if (rv != 0) {
            unexpected_error();
        }

        if (pt_size != out_produced) {
            fprintf(
                stderr,
                "Wrong output size: Expected %zu got %zu (consumed %zu of %zu) completed=%d\n",
                pt_size,
                out_produced,
                in_consumed,
                ct_size,
                (int)aws_cryptosdk_session_is_done(session));
            return 1;
        }

        if (memcmp(output_buf, plaintext, pt_size)) {
            fprintf(stderr, "Plaintext mismatch\n");
            // TODO: Show mismatch
            return 1;
        }

        fprintf(stderr, "Plaintext decrypted: {");
        fwrite(output_buf, pt_size, 1, stderr);
        fprintf(stderr, "}\n");
    }

    free(output_buf);
    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);
    return 0;
}

void usage() {
    fprintf(stderr, "decrypt [--xfail] ciphertext.bin plaintext.bin\n");
    exit(1);
}

void parse_args(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--xfail")) {
            expect_failure = true;
        } else if (!strcmp(argv[i], "--gcmkey")) {
            gcm_key = true;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            usage();
        } else {
            break;
        }
    }

    if (i != argc - 2) {
        fprintf(stderr, "Wrong number of arguments\n");
        usage();
    }

    ciphertext_filename = argv[i];
    plaintext_filename  = argv[i + 1];
}

int main(int argc, char **argv) {
    parse_args(argc, argv);

    if (test_loadfile(ciphertext_filename, &ciphertext, &ct_size)) {
        fprintf(stderr, "Failed to load ciphertext file %s: %s\n", ciphertext_filename, strerror(errno));
        return 1;
    }

    if (test_loadfile(plaintext_filename, &plaintext, &pt_size)) {
        fprintf(stderr, "Failed to load plaintext file %s: %s\n", plaintext_filename, strerror(errno));
        return 1;
    }

    int result = test_decrypt();

    free(ciphertext);
    free(plaintext);

    return result;
}
