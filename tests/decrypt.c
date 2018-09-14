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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/common/common.h>
#include <aws/common/error.h>

#include "testutil.h"
#include "zero_keyring.h"

/* Braindead option parser for now */
const char *ciphertext_filename, *plaintext_filename;
bool expect_failure = false;

uint8_t *ciphertext, *plaintext;
size_t ct_size, pt_size;

#define unexpected_error() do { \
    fprintf(stderr, "Unexpected error return (%d, 0x%04x) at %s:%d: %s\n", \
        aws_last_error(), aws_last_error(), __FILE__, __LINE__, aws_error_str(aws_last_error())); \
    return 1; \
} while(0)

int test_decrypt() {
    aws_load_error_strings();
    aws_cryptosdk_err_init_strings();

    uint8_t *output_buf = malloc(pt_size);
    if (!output_buf) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm = NULL;

    if (!(cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), aws_cryptosdk_zero_keyring_new()))) unexpected_error();

    if (!(session = aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, cmm))) unexpected_error();

    uint8_t *outp = output_buf;
    const uint8_t *inp = ciphertext;

    size_t outsz = pt_size;
    size_t insz = ct_size;
    size_t out_produced = 0xDEADBEEF;
    size_t in_consumed = 0xABCD0123;

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
            fprintf(stderr, "Wrong output size: Expected %zu got %zu (consumed %zu of %zu)\n",
                pt_size, (size_t)(outp - output_buf),
                (size_t)(inp - ciphertext), ct_size
                );
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
    aws_cryptosdk_cmm_destroy(cmm);

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
    plaintext_filename = argv[i+1];
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
