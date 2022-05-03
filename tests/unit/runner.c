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

#include <aws/common/common.h>
#include <aws/common/error.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/private/session.h>

int pass_fn() {
    return 0;
}

struct test_case *test_groups[] = { header_test_cases,
                                    cipher_test_cases,
                                    commitment_test_cases,
                                    materials_test_cases,
                                    enc_ctx_test_cases,
                                    encrypt_test_cases,
                                    framefmt_test_cases,
                                    hkdf_test_cases,
                                    raw_aes_keyring_decrypt_test_cases,
                                    raw_aes_keyring_encrypt_test_cases,
                                    raw_aes_keyring_provider_info_test_cases,
                                    multi_keyring_test_cases,
                                    signature_test_cases,
                                    trailing_sig_test_cases,
                                    raw_rsa_keyring_decrypt_test_cases,
                                    raw_rsa_keyring_encrypt_test_cases,
                                    local_cache_test_cases,
                                    caching_cmm_test_cases,
                                    keyring_trace_test_cases,
                                    max_edks_test_cases,
                                    NULL };

struct test_case *test_cases;

static void assemble_test_cases(int enable_all) {
    int n = 0;

    for (struct test_case **group = test_groups; *group; group++) {
        for (struct test_case *pCase = *group; pCase->group; pCase++) {
            n++;
        }
    }

    test_cases = calloc(n + 1, sizeof(*test_cases));

    struct test_case *pCopyTo = test_cases;

    for (struct test_case **group = test_groups; *group; group++) {
        for (struct test_case *pCase = *group; pCase->group; pCase++) {
            *pCopyTo         = *pCase;
            pCopyTo->result  = 0;
            pCopyTo->enabled = enable_all;
            pCopyTo++;
        }
    }
}

static void enable_cases(const char *specifier) {
    if (specifier[0] == '-') {
        fprintf(
            stderr,
            "The test runner does not take option arguments. However, you can pass a list\n"
            "of test cases, e.g.:\n\n"
            "\taws-encryption-sdk-tests 'test_group.*' 'test_group_2.specific_test'\n"
            "\n"
            "If no options are passed, all tests will be run.\n");
        exit(1);
    }

    const char *dot = strchr(specifier, '.');
    int groupLen    = dot ? (int)(dot - specifier) : (int)strlen(specifier);

    int enabled_ct = 0;
    for (struct test_case *pCase = test_cases; pCase->group; pCase++) {
        if (!strncmp(pCase->group, specifier, groupLen)) {
            if (!dot || !strcmp(dot + 1, pCase->name)) {
                pCase->enabled = 1;
                enabled_ct++;
            }
        }
    }

    if (!enabled_ct) {
        printf("No tests matched specifier '%s'\n", specifier);
        exit(1);
    }
}

int main(int argc, char **argv) {
    aws_common_library_init(aws_default_allocator());
    aws_cryptosdk_load_error_strings();

    int ret;
    assemble_test_cases(argc < 2);

    for (int i = 1; i < argc; i++) {
        enable_cases(argv[i]);
    }

    int passed = 0, failed = 0;

    for (struct test_case *pCase = test_cases; pCase->group; pCase++) {
        if (!pCase->enabled) {
            continue;
        }

        fprintf(stderr, "[RUNNING] %s.%s ...\r", pCase->group, pCase->name);
        pCase->result = pCase->test_fn();
        fprintf(stderr, "%s %s.%s    \n", pCase->result ? "\n[ FAILED]" : "[ PASSED]", pCase->group, pCase->name);

        if (pCase->result) {
            failed++;
        } else {
            passed++;
        }
    }

    if (!failed && !passed) {
        printf("No test cases selected.\n");
        ret = 1;
        goto DONE;
    }

    printf("\n\nTest run complete. ");
    if (!failed) {
        printf("All tests passed (%d tests).\n", passed);
        ret = 0;
    } else {
        printf("%d tests failed (%d passed). Failing tests:\n", failed, passed);

        for (struct test_case *pTest = test_cases; pTest->group; pTest++) {
            if (pTest->result) {
                printf("[ FAILED] %s.%s\n", pTest->group, pTest->name);
            }
        }
        ret = 1;
    }

DONE:
    if (test_cases) free(test_cases);
    return ret;
}
