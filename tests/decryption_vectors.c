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
#include <aws/common/byte_buf.h>
#include <aws/common/encoding.h>

#include "testutil.h"
#include "zero_keyring.h"

bool suite_failed = false;
#define SENTINEL_VALUE ((size_t)0xABCD0123DEADBEEFllu)

#define unexpected_error() do { \
    int errcode = aws_last_error(); \
    fprintf(stderr, "Unexpected error at %s:%d: %s (0x%04x)", \
        __FILE__, __LINE__, aws_error_str(errcode), errcode); \
    failed = true; \
    goto error; \
} while (0)

static void decrypt_test_oneshot(
    enum aws_cryptosdk_alg_id alg_id,
    const char *vector_name,
    struct aws_byte_buf pt,
    struct aws_byte_buf ct
) {
    bool failed = false;

    uint8_t *outbuf = malloc(pt.len);
    if (!outbuf) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = NULL;
    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm = NULL;

    if (!(kr = aws_cryptosdk_zero_keyring_new(alloc))) unexpected_error();
    if (!(cmm = aws_cryptosdk_default_cmm_new(alloc, kr))) unexpected_error();
    if (!(session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm))) unexpected_error();
    aws_cryptosdk_keyring_release(kr); kr = NULL;
    aws_cryptosdk_cmm_release(cmm); cmm = NULL;

    uint8_t *outp = outbuf;
    const uint8_t *inp = ct.buffer;

    size_t outsz = pt.len;
    size_t insz = ct.len;
    size_t out_produced, in_consumed;
    out_produced = in_consumed = SENTINEL_VALUE;

    int rv = aws_cryptosdk_session_process(session, outp, outsz, &out_produced, inp, insz, &in_consumed);
    if (rv != 0) unexpected_error();

    enum aws_cryptosdk_alg_id actual_alg_id;
    if (aws_cryptosdk_session_get_algorithm(session, &actual_alg_id)) unexpected_error();

    if (actual_alg_id != alg_id) {
        fprintf(stderr, "Wrong algorithm ID. Expected %04x, got %04x\n", alg_id, actual_alg_id);
        failed = true;
    }

    if (in_consumed != ct.len) {
        fprintf(stderr, "Wrong number of bytes consumed. Expected %zu consumed; got %zu consumed\n",
            ct.len, in_consumed);
        failed = true;
    }

    if (out_produced != pt.len) {
        fprintf(stderr, "Wrong number of bytes produced. Expected %zu produced; got %zu produced\n",
            pt.len, out_produced);
        failed = true;
    }

    if (memcmp(outbuf, pt.buffer, pt.len)) {
        fprintf(stderr, "Plaintext mismatch\n");
        failed = true;
    }

error:
    if (session) aws_cryptosdk_session_destroy(session);
    if (cmm) aws_cryptosdk_cmm_release(cmm);
    if (kr) aws_cryptosdk_keyring_release(kr);

    free(outbuf);

    if (failed) {
        suite_failed = true;
        fprintf(stderr, "[FAILED] One-shot test for vector %s\n", vector_name);
    }
}

static void decrypt_test_incremental(
    enum aws_cryptosdk_alg_id alg_id,
    const char *vector_name,
    struct aws_byte_buf pt,
    struct aws_byte_buf ct
) {
    bool failed = false;

    uint8_t *outbuf = malloc(pt.len);
    if (!outbuf) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = NULL;
    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm = NULL;

    if (!(kr = aws_cryptosdk_zero_keyring_new(alloc))) unexpected_error();
    if (!(cmm = aws_cryptosdk_default_cmm_new(alloc, kr))) unexpected_error();
    if (!(session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm))) unexpected_error();
    aws_cryptosdk_keyring_release(kr); kr = NULL;
    aws_cryptosdk_cmm_release(cmm); cmm = NULL;

    uint8_t *outp = outbuf;
    const uint8_t *inp = ct.buffer;

    while (!aws_cryptosdk_session_is_done(session)) {
        size_t est_in = 0, est_out = 0;
        size_t outsz = 0;
        size_t insz = 0;
        size_t max_outsz = pt.len - (outp - outbuf);
        size_t out_produced, in_consumed;

        while (true) {
            aws_cryptosdk_session_estimate_buf(session, &est_out, &est_in);

            // Clamp the estimated output size to the true plaintext size
            if (est_out > max_outsz) {
                est_out = max_outsz;
            }

            // On entry, outsz/insz reflect what was passed in on the prior iteration.
            // If they match current estimates, then we're stuck - the session doesn't
            // want more data, but failed to make progress with that much data in the last
            // round.
            if (est_in == insz && est_out == outsz) {
                fprintf(stderr, "Session stuck at input offset %zu, output offset %zu, estimates in %zu out %zu (clamped at %zu)\n",
                    (size_t)(inp - ct.buffer), (size_t)(outp - outbuf), est_in, est_out, max_outsz);
                failed = true;
                goto error;
            }

            // We'll be spoonfeeding the SDK one byte at a time to see if it does anything.
            // If we reach the estimates (or end of data) and no progress is made, then the test fails.
            // It's okay if it makes progress _before_ the estimates, or if it extends
            // the estimates; as such, we increase buffer sizes one byte at a time to catch these conditions.

            // Note that we know that we'll never need more than the true message size, so outsz
            // can't exceed the true plaintext length.

            if (insz < ct.len - (inp - ct.buffer) && insz < est_in) {
                insz++;
            }

            // Try parsing with an empty output buffer
            outsz = 0;

            out_produced = in_consumed = SENTINEL_VALUE;
            int rv = aws_cryptosdk_session_process(session, outp, outsz, &out_produced, inp, insz, &in_consumed);

            if (out_produced == SENTINEL_VALUE || in_consumed == SENTINEL_VALUE) {
                fprintf(stderr, "Sentinel left in produced/consumed values\n");
                failed = true;
            }

            if (rv) unexpected_error();

            if (out_produced) {
                fprintf(stderr, "Output generated with zero output size\n");
                failed = true;
                goto error;
            }

            if (in_consumed) {
                // Ok, we made some progress
                break;
            }

            if (est_out) {
                // Looks like it wanted some output space. First try with an output buffer that's just a byte too short.
                outsz = est_out - 1;

                out_produced = in_consumed = SENTINEL_VALUE;
                rv = aws_cryptosdk_session_process(session, outp, outsz, &out_produced, inp, insz, &in_consumed);

                if (out_produced == SENTINEL_VALUE || in_consumed == SENTINEL_VALUE) {
                    fprintf(stderr, "Sentinel left in produced/consumed values\n");
                    failed = true;
                }

                if (rv) unexpected_error();

                if (out_produced > outsz) {
                    fprintf(stderr, "Consumed too much output space\n");
                    failed = true;
                    goto error;
                }

                if (in_consumed) {
                    // Output size estimate was conservative, which was okay
                    break;
                }

                // Give it what it wants for the output buffer
                outsz = est_out;
                out_produced = in_consumed = SENTINEL_VALUE;
                rv = aws_cryptosdk_session_process(session, outp, outsz, &out_produced, inp, insz, &in_consumed);

                if (out_produced == SENTINEL_VALUE || in_consumed == SENTINEL_VALUE) {
                    fprintf(stderr, "Sentinel left in produced/consumed values\n");
                    failed = true;
                }

                if (rv) unexpected_error();

                if (out_produced > outsz) {
                    fprintf(stderr, "Consumed too much output space\n");
                    failed = true;
                    goto error;
                }

                if (in_consumed) {
                    // We made some progress
                    break;
                }
            }
        } // while (true) loop over input sizes

        inp += in_consumed;
        outp += out_produced;
    } // outer loop until complete

    enum aws_cryptosdk_alg_id actual_alg_id;
    if (aws_cryptosdk_session_get_algorithm(session, &actual_alg_id)) unexpected_error();

    if (actual_alg_id != alg_id) {
        fprintf(stderr, "Wrong algorithm ID. Expected %04x, got %04x\n", alg_id, actual_alg_id);
        failed = true;
    }

    if (inp != ct.buffer + ct.len) {
        fprintf(stderr, "Wrong number of bytes consumed. Expected %zu consumed; got %zu consumed\n",
            ct.len, (size_t)(inp - ct.buffer));
        failed = true;
    }

    if (outp != outbuf + pt.len) {
        fprintf(stderr, "Wrong number of bytes produced. Expected %zu consumed; got %zu consumed\n",
            pt.len, (size_t)(outp - pt.buffer));
        failed = true;
    }

    if (memcmp(outbuf, pt.buffer, pt.len)) {
        fprintf(stderr, "Plaintext mismatch\n");
        failed = true;
    }


error:
    if (session) aws_cryptosdk_session_destroy(session);
    if (cmm) aws_cryptosdk_cmm_release(cmm);
    if (kr) aws_cryptosdk_keyring_release(kr);

    free(outbuf);

    if (failed) {
        suite_failed = true;
        fprintf(stderr, "[FAILED] Incremental test for vector %s\n", vector_name);
    }
}

static void decrypt_test_badciphertext(
    enum aws_cryptosdk_alg_id alg_id,
    const char *vector_name,
    struct aws_byte_buf pt,
    struct aws_byte_buf ct
) {
    // TODO: Make algorithm ID names consistent with java and use them for error messages
    (void)alg_id;

    bool failed = false;

    uint8_t *outbuf = malloc(pt.len);
    uint8_t *zerobuf = calloc(pt.len, 1);
    if (!outbuf || !zerobuf) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    struct aws_allocator *alloc = aws_default_allocator();
    struct aws_cryptosdk_keyring *kr = NULL;
    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm = NULL;

    if (!(kr = aws_cryptosdk_zero_keyring_new(alloc))) unexpected_error();
    if (!(cmm = aws_cryptosdk_default_cmm_new(alloc, kr))) unexpected_error();
    if (!(session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm))) unexpected_error();
    aws_cryptosdk_keyring_release(kr); kr = NULL;
    aws_cryptosdk_cmm_release(cmm); cmm = NULL;
    
    uint8_t *outp = outbuf;
    const uint8_t *inp = ct.buffer;

    size_t outsz = pt.len;
    size_t insz = ct.len;
    size_t out_produced, in_consumed;

#ifndef REDUCE_TEST_ITERATIONS
    int increment = 1;
#else
    int increment = 8;
#endif

    // Verify that decryption fails if we flip any bit in the ciphertext
    for (size_t bit = 0; bit < ct.len * 8; bit += increment) {
        ct.buffer[bit / 8] ^= 1 << (bit % 8);

        if (aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT)) unexpected_error();

        out_produced = in_consumed = SENTINEL_VALUE;
        memset(outbuf, 0x42, outsz);

        int rv = aws_cryptosdk_session_process(session, outp, outsz, &out_produced, inp, insz, &in_consumed);

        if (out_produced == SENTINEL_VALUE || in_consumed == SENTINEL_VALUE) {
            fprintf(stderr, "out/in produced/consumed left uninitialized after corrupting bit %zu\n", bit);
            failed = true;
        }

        if (rv != 0 && out_produced) {
            fprintf(stderr, "output produced after corrupting bit %zu\n", bit);
            failed = true;
        }

        if (rv != 0 && memcmp(zerobuf, outbuf, pt.len)) {
            fprintf(stderr, "output buffer not zero after corrupting bit %zu\n", bit);
            failed = true;
        }

        int lasterror = aws_last_error();

        if (rv == 0 && !aws_cryptosdk_session_is_done(session)) {
            // The session wants more data before calling it (probably we corrupted a length field).
            // This is okay.
        } else if (rv == 0) {
            fprintf(stderr, "Unexpected success after corrupting bit %zu\n", bit);
            failed = true;
        } else if (lasterror != AWS_CRYPTOSDK_ERR_BAD_CIPHERTEXT && lasterror != AWS_CRYPTOSDK_ERR_CANNOT_DECRYPT
            && lasterror != AWS_CRYPTOSDK_ERR_LIMIT_EXCEEDED) {
            fprintf(stderr, "Incorrect error after corrupting bit %zu: %s (0x%04x)\n",
                bit, aws_error_str(lasterror), lasterror);
            failed = true;
        }

        ct.buffer[bit / 8] ^= 1 << (bit % 8);
    }

error:
    if (session) aws_cryptosdk_session_destroy(session);
    if (cmm) aws_cryptosdk_cmm_release(cmm);
    if (kr) aws_cryptosdk_keyring_release(kr);

    free(outbuf);
    free(zerobuf);

    if (failed) {
        suite_failed = true;
        fprintf(stderr, "[FAILED] One-shot test for vector %s\n", vector_name);
    }
}

static struct aws_byte_buf b64_decode(const char *b64_input) {
    struct aws_byte_buf in = aws_byte_buf_from_c_str(b64_input);
    size_t outlen;

    if (aws_base64_compute_decoded_len(&in, &outlen)) {
        fprintf(stderr, "Base64 compute decoded len failed for {%s}: 0x%04x\n",
            b64_input, aws_last_error());
        exit(1);
    }

    struct aws_byte_buf out;
    if (aws_byte_buf_init(aws_default_allocator(), &out, outlen)) abort();

    if (aws_base64_decode(&in, &out)) {
        fprintf(stderr, "Base64 decode failed for {%s}: 0x%04x\n",
            b64_input, aws_last_error());
        exit(1);
    }

    return out;
}

void decrypt_test_vector(
    enum aws_cryptosdk_alg_id alg_id,
    const char *vector_name,
    const char *plaintext_expected,
    const char *ciphertext
) {
    struct aws_byte_buf pt = b64_decode(plaintext_expected);
    struct aws_byte_buf ct = b64_decode(ciphertext);

    decrypt_test_oneshot(alg_id, vector_name, pt, ct);
    decrypt_test_incremental(alg_id, vector_name, pt, ct);
    decrypt_test_badciphertext(alg_id, vector_name, pt, ct);

    aws_byte_buf_clean_up(&pt);
    aws_byte_buf_clean_up(&ct);
}

int main() {
    aws_load_error_strings();
    aws_cryptosdk_err_init_strings();

    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256 hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYABFO37IzpEmc0FwZTvdUKZNmwAAAABAAh6ZXJvLWtleQANcHJvdmlkZXIgaW5mbwABAAIAAAAADAAAAA0AAAAAAAAAAAAAAACNU9yvQgmpDkhnXnIQNxa2AAAAAQAAAAAAAAAAAAAAASUlloU74HOz+Y1YlYf6Raw/tn/7oSD3tUsfzC8W/////wAAAAIAAAAAAAAAAAAAAAIAAAAAeSAQ6uk0/Gbj1GQb7AXKTw==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256 hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYABFGFnpBnRQb1tMqjYPdKOqIYACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAAKeI+/USYAoL5xGuEd4UpFD/////AAAAAQAAAAAAAAAAAAAAAQAAAA0lnpNe/RerbazP3UBrbs1eLvoJAJg/KfCMQ8uNng==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256 hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYABFNus0VqHpji+wO7AO5Lp+kkACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAAOvAACrzHn8+Y1k4HGz1rskAAAABAAAAAAAAAAAAAAABVmZY8rCLyome+6bA81VBHrsAAAACAAAAAAAAAAAAAAACgCPkE+LwBm4qqqIoB19eSF8AAAADAAAAAAAAAAAAAAAD0zO/NwrGVbZQYTACuFJhtt4AAAAEAAAAAAAAAAAAAAAEt8kUu4ECVtLVBUifQjiaqzYAAAAFAAAAAAAAAAAAAAAFUGbHLA1l3uhCPbdu4QwP+E8AAAAGAAAAAAAAAAAAAAAGpdLWGzgWkvcmEF0YWcH19WMAAAAHAAAAAAAAAAAAAAAH054BqrmMfoAfQmSjV5IwltQAAAAIAAAAAAAAAAAAAAAI006QgZ/tKDG4otj3UyHnsoEAAAAJAAAAAAAAAAAAAAAJuVkwonf0gIr/8HOUwiDyfBMAAAAKAAAAAAAAAAAAAAAKSv127hhPUWOrNz1usuZ7PdgAAAALAAAAAAAAAAAAAAALk0LycGkVH0qkRZIpIqBwg0wAAAAMAAAAAAAAAAAAAAAMVRRzCYEsJjY6OsvE2uFOtDMAAAANAAAAAAAAAAAAAAAN8cf0AcXPTdDoy6YU4s84NQH/////AAAADgAAAAAAAAAAAAAADgAAAABt8AHcYIqOrDS/AKwwNysy");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256 hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYABFDxIbFxQ7KluoyhDyKK81bAACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAAGwi2w/SJ1AluPOGEYVhr4sAAAABAAAAAAAAAAAAAAABW0Yt5hr+j4dcruyyJhaM5RXxAAAAAgAAAAAAAAAAAAAAAo7J5wEMoMB+uy/rg2CMEEXP1AAAAAMAAAAAAAAAAAAAAAPUTeJVIUCXznMjduSAmmIRdNgAAAAEAAAAAAAAAAAAAAAECfLHs5NABXRUsHir0vKy8FRdAAAABQAAAAAAAAAAAAAABTU7iWnrXj8iWjYDRQzSR33sFQAAAAYAAAAAAAAAAAAAAAbQX9jatJKKzVBsWZ347M1GF23/////AAAABwAAAAAAAAAAAAAABwAAAAEvjRjv5rtQzHkSHMQdcg+mnQ==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256 hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYABFDwyvHTnEv2QMTujaeZB/fkACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAAA2h29clG6EQxaX1DEgFShYAAAAAAAAAAAAAAAEAAAAAAAAADYmuWdgpn9YqO9hBgc1GeQns9X6M8A9dWikjX+eO");

    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYACFPHZAZOaABAjScKPLj2wum4ARwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkALEE1M01FZmhHanhGQnVjNlJWOXVGeGpPUGhPRGsxZUpFT0RKZTVMTnpsdTZPAAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAADQAAAAAAAAAAAAAAACP5kqNx/M6wYU1UMNKN3Y4AAAABAAAAAAAAAAAAAAABM28sLCeybDYoVfr731SUqnhrE22EP5UM/wEeHSj/////AAAAAgAAAAAAAAAAAAAAAgAAAADjABzOysg8RecIGoIYgSajAEcwRQIgFPJ/ledtQpFBA/jFnhOFp3zNv3R2to59dK56S0ex2q4CIQC4hKm1cRuJSqeOrUCLdLlnLifDG7bimvT3xx9JVOKTNw==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYACFOQFm29zDxg2G+qyIGGxEfAATQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkALEF0L2lKek5adlhjSEw2R1c4UHNzOG5SYkJPNWdSTDRqSnhSS3d0aU9hTzNwAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAAFauIwVWRYR6Z1x5y4TOG+T/////AAAAAQAAAAAAAAAAAAAAAQAAAA1/l2k66qgC0pGV/gZOSMf0HcWTB7QTdQhTXQWoxwBHMEUCIQDn10IqxQVxbQY/VwITYhodCnTL1yc1Eu3OjP7AsikxsgIgHiEZTK7pB+ti7Wo9WdUlF4jyc+SwljAz8HUoeaGm03g=");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYACFOIIjrwJVMSesXWRKam101AATQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkALEExQ2toS0JvcUtNcm92SDh3T1AxSWpUeWRBdnZnRW5zdmhxVUw2cm16RmVwAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAAB+ocV39cEN9LeoWb8MRGT4AAAABAAAAAAAAAAAAAAABqtbr5Yfdu8WPsuK30DHRrZQAAAACAAAAAAAAAAAAAAACXl7eIOVkKubpz6EzZYi0MZkAAAADAAAAAAAAAAAAAAADZE2hl//RMhCusU6LutdicnEAAAAEAAAAAAAAAAAAAAAEl+qDYdeRBQFP+rbA1U5PVa0AAAAFAAAAAAAAAAAAAAAFOoWlX3vFpYDQht9GHgO+DVYAAAAGAAAAAAAAAAAAAAAGHIY7sVz+YkVsluJGfObpgxMAAAAHAAAAAAAAAAAAAAAHbvH3XlKPBw3CpaOnb15XFNMAAAAIAAAAAAAAAAAAAAAIL6X/+0xp0JGfsrjEbxPcnNsAAAAJAAAAAAAAAAAAAAAJelZOI0yqQZVgegFR39zyaz4AAAAKAAAAAAAAAAAAAAAKn4VhqiCyyhJqDDi/eMWRbUYAAAALAAAAAAAAAAAAAAAL+cCzPFvFIKbtKgmb9c8ujbgAAAAMAAAAAAAAAAAAAAAMs6w79A6b7QYL9Mn9qrctgqoAAAANAAAAAAAAAAAAAAANCpqMWCyEI4D25PuIBjDW9lT/////AAAADgAAAAAAAAAAAAAADgAAAAD1JaCZlSMi2iU8ELG5HLBAAEcwRQIgF1H9nJNbk7EMgycHewKf+Qo5keAxuXk8nJ/CjijiuZoCIQClkGSB4/eeqmVplQ9M1M0b6vCD7WZbvDe8CSs3crUimg==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYACFBhaEskkY72+3DrI/+Ol8xMATQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkALEEzVXJBMU1zZ1hOc1VBUWNLeWJjdjRpUW9QSDUxNGRBNzZmdTR2cWY4NXNRAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAABJGyNQ4GygxhEruWbjw/U8AAAABAAAAAAAAAAAAAAABTaX1sJa6h8Ibt5WyWds2jBMzAAAAAgAAAAAAAAAAAAAAAlS39gqMTlwn4A7sNnoAjeQezQAAAAMAAAAAAAAAAAAAAAPSrxUc2yPXWayzCYL5k+wowGwAAAAEAAAAAAAAAAAAAAAEP3cWjJ1kfWNT4lrhn2vSiJGyAAAABQAAAAAAAAAAAAAABfj9QXLQfk8vKnYN7WkPjfmgiAAAAAYAAAAAAAAAAAAAAAZxFeGdMon55mTtjFYPArKOBjX/////AAAABwAAAAAAAAAAAAAABwAAAAEIdjKadbLYkx8X6lKgDa3W/wBHMEUCIQCjf/8fThLkBJqdOx6FOcMAAaPRijgpJXzrHW0UL3TABwIgertYlaatcOmuPcgYoYLft1RW3KJjaZVx/w+m2D0w6ao=");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256, "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYACFIWnxDJJfDNaWQS9UQFqPmQATQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkALEE0RlVxTmlQU28zNGNZRVZkSzlvYnVjOFpBNS82TS9mMTYwUHQ0Rk5Xdkw0AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAADMPDUNRMdpbI0NRYDrfx4EAAAAAAAAAAAAAAAEAAAAAAAAADRY0BUIj/dw/klghtmHXDIpewjacrHve4MnuihqQAEcwRQIgXf6ZpeLgJJENLriizi15PxPdGh/GRCvRez/X//TZMKgCIQCZ2RbgP8CnuvXgfkxRxN8+wt8lIw1ZGai3kW8Y8vrZFg==");

    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_NO_KDF hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYAAFF5xckOKE1oNWiunN7uKiYoAAAABAAh6ZXJvLWtleQANcHJvdmlkZXIgaW5mbwABAAIAAAAADAAAAA0AAAAAAAAAAAAAAADUMz8/TawzJXmNv/F3A4WFAAAAAQAAAAAAAAAAAAAAASZktVxopFLKNECA8ESngDGpty1tYaBVbzfbr41F/////wAAAAIAAAAAAAAAAAAAAAIAAAAA5KJqTmsljM6HY2V45Zjvaw==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_NO_KDF hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYAAFOZ3Aqp4WVh6KPn8erOQfLkACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAAD6m+8R/b39IdKIfTA2RI0L/////AAAAAQAAAAAAAAAAAAAAAQAAAA0mZLVcaKRSyjRAgPBEoGKZELGfrj0PpyW88u51GQ==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_NO_KDF hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYAAFDOjuvVh7DSc3BPFoNxO9/IACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAAMq6+tVeipBpGZ65Gn7VPFUAAAABAAAAAAAAAAAAAAABJtYKs+IEthZjF56Z6W24RaMAAAACAAAAAAAAAAAAAAACtBuOLDMDiRTSMC7vWZtfB8gAAAADAAAAAAAAAAAAAAAD79afjuHozXBx8up4sWi3xToAAAAEAAAAAAAAAAAAAAAEd0xraXUjhuLbZzwFqWCxRakAAAAFAAAAAAAAAAAAAAAFuMR465uCFInT2vjKggamwmwAAAAGAAAAAAAAAAAAAAAG7shGhKJeMSRnd3On1MM4iuIAAAAHAAAAAAAAAAAAAAAHCVCr36B4HMqY+/5Exq9Wt7UAAAAIAAAAAAAAAAAAAAAI/A2K64OWtms43cz8uNVtvrMAAAAJAAAAAAAAAAAAAAAJK5JaKMY/UPuHC1Hvab8A0hcAAAAKAAAAAAAAAAAAAAAKSQHYjFHAvPvsiFmAm3n4ZBAAAAALAAAAAAAAAAAAAAALh8jAcNZhMUBRX0YaE/EYLrEAAAAMAAAAAAAAAAAAAAAMknMHjJsT922QWhm3j6X7dE0AAAANAAAAAAAAAAAAAAANn2qQY2GEovWOS3Lv8FK1mx//////AAAADgAAAAAAAAAAAAAADgAAAAA0PBOjjlewHQO/2epwPspQ");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_NO_KDF hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYAAFE1QhTrSl6Edmg36dlG/rUkACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAAJ5pUcE2BeIX8pQ1cJHfgNUAAAABAAAAAAAAAAAAAAABJmREjkwLKjcE9pMedqoH8YYKAAAAAgAAAAAAAAAAAAAAAr17XId6aUNjvsUYhDQpLMi9MQAAAAMAAAAAAAAAAAAAAAPspNCY2TCJmS6f5dsN720OvyoAAAAEAAAAAAAAAAAAAAAEOzbrVS9M/3O8JkZ5pygNux8IAAAABQAAAAAAAAAAAAAABbjvYF6IDtbD2nL+9E4Y1DStVwAAAAYAAAAAAAAAAAAAAAauNeKnFG+Ec1XnONhOc4a8aA7/////AAAABwAAAAAAAAAAAAAABwAAAAEIQ9XvYj8ItfQpuXczzxqc7Q==");
    decrypt_test_vector(AES_128_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_128_GCM_IV12_TAG16_NO_KDF hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYAAFKX9rZA/1DJQTmxcEwOGOXMACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAAIeNmlCdCMcVqPFGhDv5vCMAAAAAAAAAAAAAAAEAAAAAAAAADSZktVxopFLKNECA8ERS7+0LwneNHHV8nWxqrOr2");

    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256 hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYABRm5oyPUmfXPpQVjn4t5N8wMAAAABAAh6ZXJvLWtleQANcHJvdmlkZXIgaW5mbwABAAIAAAAADAAAAA0AAAAAAAAAAAAAAAAjRwdLHETfUHAezZEoT+u0AAAAAQAAAAAAAAAAAAAAAYFgSSRBRk3Yt9guC+ukNHh3imXerE9XETqdCy6p/////wAAAAIAAAAAAAAAAAAAAAIAAAAAwGeY5DF+pUiJJX+Yb/ZyQA==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256 hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYABRuEjwrekPCLXYQwT7+yAvh8ACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAAK/uwF/tCxnphIljBszyh1H/////AAAAAQAAAAAAAAAAAAAAAQAAAA28+gIcKjCnuI6SqPy6BJQjrDTrQSWd6O/tvOUbvw==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256 hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYABRmiPuY3hzKw9Jt3qELn0xmwACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAAPVx3qVaHLf+S659lYjojI4AAAABAAAAAAAAAAAAAAABnv6OICDk8zCYbK0dSjwPC2AAAAACAAAAAAAAAAAAAAAC1AAbvhryD6lZjMIr1vEph4YAAAADAAAAAAAAAAAAAAAD1+/FghXn9nPu5hEOfaHQzrgAAAAEAAAAAAAAAAAAAAAEZg04o3mLAj1awq9O3In17qwAAAAFAAAAAAAAAAAAAAAFhNSsYTBIbmPPlVax2ECa3g0AAAAGAAAAAAAAAAAAAAAGhzHGrc7Ydf4990fIW4ryW6MAAAAHAAAAAAAAAAAAAAAHRWKrmJM3mnMD0JEMvbdUAwsAAAAIAAAAAAAAAAAAAAAI49JbVz4NRvEa73nMAAi1vzkAAAAJAAAAAAAAAAAAAAAJzNL2CQaOuCMD+/+uFMuVfNkAAAAKAAAAAAAAAAAAAAAKACVCnHRrZG3erquxl4mPxPYAAAALAAAAAAAAAAAAAAAL/GlNUdy7Peed6I0GeXyQztgAAAAMAAAAAAAAAAAAAAAM/AgLvNtGAcKXlXz/ArIXdpMAAAANAAAAAAAAAAAAAAANq/32rMIlGYVMs6YmqfWicJz/////AAAADgAAAAAAAAAAAAAADgAAAAAVqOW8ZMOmmwRs4XQvmUDV");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256 hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYABRtcYJm9d5cEs/LMQVdjik6EACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAAOODyFV7fYsPHOT4qFdArXgAAAABAAAAAAAAAAAAAAAB1qPKqv5weF9KHNc9h38xNhMpAAAAAgAAAAAAAAAAAAAAAsqRxYA+QXPQh8Eno9NiYDpEPAAAAAMAAAAAAAAAAAAAAAPnm7cXCwll19r4qjkhJrZMFmUAAAAEAAAAAAAAAAAAAAAE0qIcN6TxZ8qF4nwMZHPTETW5AAAABQAAAAAAAAAAAAAABTgy4TaeE8vqSnlSvuB+vUFAzAAAAAYAAAAAAAAAAAAAAAZS8/dI5TQlAYI1NgnvAX1EPvf/////AAAABwAAAAAAAAAAAAAABwAAAAGNQsYPKQQ4jsj94hb+pXGuzQ==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256 hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYABRsY+YBhkrNWf3TvHKiz5RSAACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAAE0B7QJ5dmbBiWoHMcIb8nIAAAAAAAAAAAAAAAEAAAAAAAAADdFnTWKyFSsWZuhVvx+EjEYNAoZ8qlh9DFQRoIvm");

    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYADRg9rxGlCu+7HTzUfEG74GbQAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFtUHlsWHJCSUNSUDFXVHY3QU0zWjNTMG1wbUhNN2xzRUtOL203TnhaZXdHOEZrSU9qVDJYL3FkM0Q3aHRmU2Q4UT09AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAADQAAAAAAAAAAAAAAAAs7MT3OSHDnlpIWo1qwq6gAAAABAAAAAAAAAAAAAAABjc6wmeXNKLR9CohPJ2NPkumz2dmwbnHIbc1WU4D/////AAAAAgAAAAAAAAAAAAAAAgAAAABYh6g6sZNyv40Kw4CxlAAmAGcwZQIwRJH+014gYdqFBrAn8j51IugE8z/et4moDy9bqvberfW2hpSeQH9h5KvzzvKlUSUeAjEAtrKFTGrLHKJUgZaZb26AZPaqNf7EZVe+VLojwdhev/mTJs8d9IIQCRu7iQtPNGdV");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYADRqFn0cd56okMXixphCGsoqIAZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFzeXpxTEZrU2JLL2JCSlpITm5GZ0ovbXVjdm5zN3YvNlMrajhrNGR0aEFyT1pWbStidEFhWHd0aTdHbUZhbFZzdz09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAABVQ4QMIeJgz1LZsVIPY0Mf/////AAAAAQAAAAAAAAAAAAAAAQAAAA0Vej8aLWwUzzUtdnHGkX0qLPgjYXzYJ358bdk51ABnMGUCMBuLwCmaVQG6tcZCMsGQ3NbmwsBGAfNRS9bVyxwMWCAXbHLpgfyGIR3CxqXPhs+1iwIxAPE1yRog7GJ3Km4pifn7OsLgMjC1K7MC0aIA7ze33CeL4Z6610VAuYv0NDCh0YSJ9g==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYADRpQ+Lzj4mLgD8iJ5clC7GwIAZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFwVTNRcUQ3T2c5WDA5cEU4eE5QdGtNZTJhU2x1SEJZSjFjSGUzSWF1VWNudUR0WEpxRmx3UXBhVUVQamZrWW5lZz09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAAFaArbNY6P3fE012tZ1NNRUAAAABAAAAAAAAAAAAAAABqaey0L8A2tZseQaycQb61UgAAAACAAAAAAAAAAAAAAACkSa6nq4jnrfFRYLtz0O9Z0MAAAADAAAAAAAAAAAAAAAD7ZYK67mgl+hSQq7DJ+7R0m8AAAAEAAAAAAAAAAAAAAAEYokA/grHRWJzWJeCdowUi74AAAAFAAAAAAAAAAAAAAAF2HFcq3zFkDO6MtPWPvhfIq8AAAAGAAAAAAAAAAAAAAAGV+CdlUyD1DTH7Nl865hlBLMAAAAHAAAAAAAAAAAAAAAH98trqBE/8F6Of/HwQ2mOslAAAAAIAAAAAAAAAAAAAAAIEzvTeIQRSytK7dxQOdcgZqgAAAAJAAAAAAAAAAAAAAAJWxuVe6QxIJwoyjp5upNnThYAAAAKAAAAAAAAAAAAAAAKUJezXcaQyPkYMtsSPwnnmBkAAAALAAAAAAAAAAAAAAALuabDyKawORX/P4SjXinFmj8AAAAMAAAAAAAAAAAAAAAMCmKco+4B2WnmboCUcrIwUAEAAAANAAAAAAAAAAAAAAANfOLo4m/CYqrK3FhbBiInMJT/////AAAADgAAAAAAAAAAAAAADgAAAADb/O55iycvvUIU9g+8Ok3cAGcwZQIwW254P6w9n1O5cek1vm+baS61CxU+uUEbLE7jpN87Ft1Gw3abtGsnwubFv2KhOS6iAjEAi78h/BjnqHR98hxnrH8W1HbCHa1Rbw8sYtO/hW6oCtuOsa2szEt/CT4+MySnGJLT");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYADRhEyCNR09tHM77TpJEqfGOUAZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFwZDZZU0VKYUsxbnAxSmFDRzd2bnkvUDAwWG92Y2Q3QTF3N2h0OEpmOEpYaHhXNXc4SW9lb2tzQTgyNkxnd3BrUT09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAALGZeQtxjMQd4jfbUFn7T2UAAAABAAAAAAAAAAAAAAABLTxxodL552ufZzsGEV2UcXIXAAAAAgAAAAAAAAAAAAAAAn47yDVklJe9UPrVuqOszJJW7wAAAAMAAAAAAAAAAAAAAANsZBf+Bx18uig8dvYzUnGYQYMAAAAEAAAAAAAAAAAAAAAEywv3T0pYgtQA3jvMZ1kPOavuAAAABQAAAAAAAAAAAAAABeiY35Q9nnTUkz6mEIbSHAyP4AAAAAYAAAAAAAAAAAAAAAbZGB/jSQyKxMk4XAnlJIvpi8D/////AAAABwAAAAAAAAAAAAAABwAAAAGZ1KEvsTAsnrx6lYgcOtMyAwBnMGUCMCJzdhNyqqwpxuTpEkkph9uNDQb5B1vS1w0heMoWEqDrmguSWEcDjTEtItGwCY6bfgIxAPhL1o9tqlfEwCyetP7xruBt7OzIBhzI5NF6UWVOh/QhNDM1YOF+KLSi4rAQbfgARQ==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYADRqfBlRuha0UWw9bTGIsZC/0AZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF1TStKdFZkTzBGZ2x0VzFCcnhvL1dBcnpzTFF6a2VBaTVmUEErOXQrZjl5SUJZR3g0c0o1a2Q3U1p6SHR2d2xvUT09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAAOFitmyAD0s/vWWsUSVc0G8AAAAAAAAAAAAAAAEAAAAAAAAADclJpp+AkP9s9vUqZoMDFjapt9c9Jb8M6mfnJv2IAGcwZQIwYuTMKP0DtQmuRNL9/HcMGk7BgHKnrKymJfrCv1mCsudDvm+N6YddiiA8xrRTN8/NAjEAxzp8HFINTYh9SW5z6jUoQ9dM4CVe25h3VWP4MaRrjg7YpTRwt6CVHD0NePGV/N17");

    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_NO_KDF hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYAARltzJ+I6RvbncCZF9BrXC9MAAAABAAh6ZXJvLWtleQANcHJvdmlkZXIgaW5mbwABAAIAAAAADAAAAA0AAAAAAAAAAAAAAADdWCkRMkHYILmoq+JLO8EhAAAAAQAAAAAAAAAAAAAAAUJN2M5nmspEMCdEVeQ31rH/1AydCVlBxQ2cGQrI/////wAAAAIAAAAAAAAAAAAAAAIAAAAAsQ0nyqsjRN+NrZ9sY63qrg==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_NO_KDF hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYAARrmDQxehMj+uCYYvST+0fywACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAAAwD8ZC+P5LMIrtrb1KKzE7/////AAAAAQAAAAAAAAAAAAAAAQAAAA1CTdjOZ5rKRDAnRFXkjBuRLfzPkQg7euQpe/wTRA==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_NO_KDF hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYAARmaz0SmGnTUXsTrlNcmcy8wACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAAAT28DNJnn1WD76oiRJ7O0UAAAABAAAAAAAAAAAAAAABQl2fusjZM4UX1dZ4qzt0MiMAAAACAAAAAAAAAAAAAAACxPsibjToHNls8EAhMOeo6N0AAAADAAAAAAAAAAAAAAADXMr/cxdFslYiXQsY/QQXa5EAAAAEAAAAAAAAAAAAAAAEdOaPf587egk//jh6y4gYCVEAAAAFAAAAAAAAAAAAAAAF+s8Xi/MO8nqH2CyOk+ZiA5IAAAAGAAAAAAAAAAAAAAAGPTMJfh0h4+7J5xEeb26Z/OQAAAAHAAAAAAAAAAAAAAAHeyqC1Fo/Zh/x7Z5pA8WFdMwAAAAIAAAAAAAAAAAAAAAIv9gPqfvYEDm1wRz4oQYQ8r8AAAAJAAAAAAAAAAAAAAAJjVE5ispaQPivEPOGOMrqL0UAAAAKAAAAAAAAAAAAAAAKhEDcdiYMqG0yN83EfO9vy+8AAAALAAAAAAAAAAAAAAALYW3D2MokXm2ywC+P8GXNMqQAAAAMAAAAAAAAAAAAAAAMab/OscU50oIL/q7voCRNsvwAAAANAAAAAAAAAAAAAAANShMF1hOowMH982KuEYBcYzn/////AAAADgAAAAAAAAAAAAAADgAAAABG8+1AmCqfW+bDFQBEeXQY");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_NO_KDF hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYAARuXtZvJzoO/IjnVyNhJE3aAACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAABbGfwbBZ/WkSCrhM0kOL5oAAAABAAAAAAAAAAAAAAABQk3n0bf7XkrhaokQMtOXMYa1AAAAAgAAAAAAAAAAAAAAAs2OJf9Gle6zhXApN8pzfjGBVgAAAAMAAAAAAAAAAAAAAANfYCc3H89CjIyS7Z0EO897QAMAAAAEAAAAAAAAAAAAAAAEOO/8wquVd+NGdcSaR43bRGKGAAAABQAAAAAAAAAAAAAABfoWFa1MIab7LMd5WHOGi5R56QAAAAYAAAAAAAAAAAAAAAZ9mrnls1kPeZx8xW341gYsOE7/////AAAABwAAAAAAAAAAAAAABwAAAAF6xdg781U8syzhBIE7Cv1Tow==");
    decrypt_test_vector(AES_192_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_192_GCM_IV12_TAG16_NO_KDF hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYAARmIAhr4VEa+Bv9eEfChWoyMACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAAA0e4uvE1RJouYd805lpJDsAAAAAAAAAAAAAAAEAAAAAAAAADUJN2M5nmspEMCdEVeT8zYYYWBuidfK0cxFWpRJt");

    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256 hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYABeA+HZH1VXNJkJDiOe88GLUIAAAABAAh6ZXJvLWtleQANcHJvdmlkZXIgaW5mbwABAAIAAAAADAAAAA0AAAAAAAAAAAAAAADjgx3lXL0pnTLWUMiV4WvHAAAAAQAAAAAAAAAAAAAAAdtweR9piMW4vrjG9a+1H/OTmHYu0P54W7bcPCaw/////wAAAAIAAAAAAAAAAAAAAAIAAAAAfMCdJNfXg2pwKnVGgW0axw==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256 hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYABeObvmIQaJEc3kxhISh9U63kACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAADpH6ZmyeVMJm18h7gyQiDr/////AAAAAQAAAAAAAAAAAAAAAQAAAA2eD0aL77aZMTjQWRLur0ipoQ7Fdv0H2x6Vxjk6fA==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256 hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYABeKq6F1i73ZOCVArZT3CWuvoACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAAMyUEj13+bm8TQ4BfszmESUAAAABAAAAAAAAAAAAAAABdKMfasSfmT5UE8+zM/zj6tMAAAACAAAAAAAAAAAAAAACWy5tnhYvz0xQBO8TjAXgeJgAAAADAAAAAAAAAAAAAAADuiOr0r7VOcxOsi7Yr7Qq4GQAAAAEAAAAAAAAAAAAAAAEfrMWAxRhLMXRmV7rZYqxatAAAAAFAAAAAAAAAAAAAAAF+EBUUSQ0m0oNgLQnGVJSAdgAAAAGAAAAAAAAAAAAAAAGvXdW3hd1TdN1422Ov5iLtD8AAAAHAAAAAAAAAAAAAAAHvGP1ivIVCEQbqLp0KHOt3KoAAAAIAAAAAAAAAAAAAAAIkt+bXhQeYHHULTj6RaxYHw4AAAAJAAAAAAAAAAAAAAAJxh2nIZSOfUnSssqGbbWte8sAAAAKAAAAAAAAAAAAAAAKNGTTIik74HtX80ecRperJHQAAAALAAAAAAAAAAAAAAALJ2cDfLz0huWlT+ZtLcGpX+UAAAAMAAAAAAAAAAAAAAAMz01zENEA7qdelIzPARCXfo8AAAANAAAAAAAAAAAAAAANo8gyl7hgOCDvsf5UJkRwEnf/////AAAADgAAAAAAAAAAAAAADgAAAADN7JjJ228ef5aKHWw7n3KD");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256 hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYABeFdvd8bsf4YRWdyV36P+JoMACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAAGst4+kS52/Eo788MjItwSQAAAABAAAAAAAAAAAAAAAB8hB5ij0LCFjZ4QqmNS6FYDDfAAAAAgAAAAAAAAAAAAAAAgGyK0eRpK0ji5p6zT+1MbcDTQAAAAMAAAAAAAAAAAAAAAOodD5bvLUIyP/MhhmYCdqk/w4AAAAEAAAAAAAAAAAAAAAEgb2/B78dN4D8DO2YfA/BNssAAAAABQAAAAAAAAAAAAAABV6WuXfQJla9CXoQ/X/PRGRZkwAAAAYAAAAAAAAAAAAAAAYamo5bLxSirsZ/JkYB2wBKFMn/////AAAABwAAAAAAAAAAAAAABwAAAAEbvEzdGW3D31v7j8a7gL/TIA==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256 hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYABeHDFMum/fh2NG7gnoFL0EzEACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAALDNdN7ONTBhTMAE4cy/ShwAAAAAAAAAAAAAAAEAAAAAAAAADaTIWuX42FuxdPJyFjdnRtrnHSuy6hsykfAXYisj");

    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYADeLxh3PMk/yStHfPV572v3s4AXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREE0ak9YZENRK2VPWlFrTWF5dXJXOUZCbFZ2eWdFK3dNUjJZRm9EZy9GdXc0Q1hBZS9WQitpMG1Ma1VVTjdRY0RjQT09AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAADQAAAAAAAAAAAAAAADWJ4AukbFt1nc9eN0r8ywUAAAABAAAAAAAAAAAAAAABdx1J/4OSHg36eryWQ/idZ8ysPenzDKNHEE7hDvP/////AAAAAgAAAAAAAAAAAAAAAgAAAAD6rYT9bN8Hk5kzPtihOz1YAGcwZQIxALagDj71EeFFmcE5UJ+9nrXOvkaboFkRStMtnTBUj/ymCEhTOtFzpSgB16QLmYWXuwIwFsTrV6fdHYjgTUnTT+fvZ+uAyc2p8fm0ok/N3RG7VhXvn9n/updZoO9tTsICSCLG");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYADeIi+rvXmM4TGIDSW7uwKgYoAZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFzdU8vejJuZk5pdG5BSDdob0tkQldPdXV1Z1BLak5iZnZONDA0VklKRFlSd0ZKc2ZiZ25YWmRGSUZsT0VZRGlYdz09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAAHuwnq3EdxXy7d2eqAPwLDz/////AAAAAQAAAAAAAAAAAAAAAQAAAA0g8Fo/yr3RRU5CQLlqiOt3zw8rt8rkVXXzNVBDOwBnMGUCMArDC2poCA5k/sFQw+ZvjnpfNoYjip2nnu9gU6J+d6j2zGmc9QdxgegyzfTHJs+t/wIxAOopIG4kq0AQKSXtiqdEsJloW4mR0JSJIl5JJg3K76G2h6NjyK5ifmVJK27TsHiw8A==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYADeAGssKK9Jnpl5Ua/5Z2jFvEAZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFwZ1NvWEJOeFZTRzZBR0JiRDhTSTZwTmNuWHBKV2QrdlpENjZuSDQvSkJyN3E4K2VXQlE1em1vWHF0M3VXSUpQZz09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAANH6EgBzNPwexFZpgSgoLdUAAAABAAAAAAAAAAAAAAABzZEnigU5444/yGy/xOwl+fsAAAACAAAAAAAAAAAAAAACX7zfAABYGF8eb0EQuNUXuNsAAAADAAAAAAAAAAAAAAADBCfirl1FZHDUpGKUR6g/TRwAAAAEAAAAAAAAAAAAAAAEit0Sb9vbmzK/PNK+cKxn8moAAAAFAAAAAAAAAAAAAAAFrOzSV01GYyq7KM66Xa4lisMAAAAGAAAAAAAAAAAAAAAGaoXowS3/5vS2uR9/bDtVByoAAAAHAAAAAAAAAAAAAAAHENQoWn3I4ppN/xRzjU8C+kkAAAAIAAAAAAAAAAAAAAAIuiLlpiex+dongFe+Iu3WgLoAAAAJAAAAAAAAAAAAAAAJtWoxEcjPBjdeLY59wjRfl6UAAAAKAAAAAAAAAAAAAAAKxsSkC+EtbLa7ineibpxN1IUAAAALAAAAAAAAAAAAAAAL/Y17BGlUuRYZhErEyW42dTQAAAAMAAAAAAAAAAAAAAAM4MGYu+OA5gmxxdrWl5/YciwAAAANAAAAAAAAAAAAAAANYudIMkz9E9BtAoqFy8dDKv//////AAAADgAAAAAAAAAAAAAADgAAAAAPIIrkKM2PiuCmkAvWAt+XAGcwZQIxAL+9GD2bw/MEjaZbwq1Iuym7+2O7K0luVZ1979oM2+BwlC0nWJWhvGI+Xi7pPfuDOgIwaQyjH4InsXDkz5vCdtETYcoV4AAUnLItQgDYBGMyYKeU34YUatTqwX8QF7bXFrn/");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYADeGxr7150r9hMHqI1xA45P0EAZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREEraUNXK0MySDFlS0JGOW9PZGNDQm1wUUFsNTZKb2J1MzEzNHlmMTVkVmN5QTZvdmwwRWllU3JreXBiV1didk5FZz09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAAHlSz3C8mi21nTJNG0hXna0AAAABAAAAAAAAAAAAAAABLZj7BXyYqs3xJvC+fBDrKbmcAAAAAgAAAAAAAAAAAAAAAjMM7VTfQXHbElMXZVyfGHBGAgAAAAMAAAAAAAAAAAAAAAPMgufOZqQpCuau09Rv8fhvPL0AAAAEAAAAAAAAAAAAAAAEhKGiXHbUDN+FV3ONKBkX/VlbAAAABQAAAAAAAAAAAAAABbfLY+0FkWF2oxCiLcX1YDwM2QAAAAYAAAAAAAAAAAAAAAbYiZAubJyXPS6LwoR9nkvDGKz/////AAAABwAAAAAAAAAAAAAABwAAAAHWbtQmvy+SRYZZraZ7d4noVQBnMGUCMQDbliScmNcO5JR+kxtjLADrbd3b7jdlGsfttT2jboQjUMa67hPTaKLPhq8N6HrwT9UCMFJ5LSK2z155iEL6FisY5394bAtJzSOVKValQB7AI4wiMpzoWFiAS00zHM+e/q/OMw==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYADeG4aJ4qAWLC+KnePsl1FVCAAZQACABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFtU0hiMm1jdXMvYVM2RkJ0NXlDNzdhY1g3NVdsT1dxNDdUUjJhbVAxVnQ2OHQwY1lNbEFqTFlrdFJPR3JWYUFKUT09AAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAAJM1DKVcvpM6cy08CcLHbAoAAAAAAAAAAAAAAAEAAAAAAAAADQlBKUuPEnJhugnJgqCtmDUG690eSMwjZWix9bGkAGcwZQIxAJX0uuCSRv2ragL3SWPMMydl7atDAJY6JpFjIQqLDTGr7CBPRccAt3AdeN6c4xhkbAIwfdSR2j7GvEYh0x0YyxQ+LDvIhkFHKzHuSvT5yEVNYW7EEwtjYpfUbWACTv968Nwo");

    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_NO_KDF hello empty final frame", "SGVsbG8sIHdvcmxkIQ==", "AYAAeDTKJgzts/VF90mc78T0y4QAAAABAAh6ZXJvLWtleQANcHJvdmlkZXIgaW5mbwABAAIAAAAADAAAAA0AAAAAAAAAAAAAAABdhL77P+bwtlNKUop22ZImAAAAAQAAAAAAAAAAAAAAAWGkSE6bWkerxnIxxbCSH6bjVYkyC1vUGAQe4ikL/////wAAAAIAAAAAAAAAAAAAAAIAAAAAjmYrMd1jZZbp1SMMvPRTmg==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_NO_KDF hello large frames", "SGVsbG8sIHdvcmxkIQ==", "AYAAeCpbDV3wvHCbTC3qd816uCkACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAQAAAAAAAAAAAAAAAAAMHWUpisEAtkGDq4mIib0Qj/////AAAAAQAAAAAAAAAAAAAAAQAAAA1hpEhOm1pHq8ZyMcWwEFLX37z78vWuOMS8ow5GMw==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_NO_KDF hello one byte frames", "SGVsbG8sIHdvcmxkIQ==", "AYAAeLjUyiKOtB6T0MVJsRVRvaoACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAQAAAAAAAAAAAAAAANQfrB4zJ2TwGUVbPPbnaHkAAAABAAAAAAAAAAAAAAABYRcnYDR2jRfZGABxTjyQUR0AAAACAAAAAAAAAAAAAAAC2/HDHxmLALwKJLT/gat9Wo8AAAADAAAAAAAAAAAAAAADx4SJyNW/dpbH6U6WKyr2vwgAAAAEAAAAAAAAAAAAAAAEpAnGy/7yfzx3Mlc4qjgGKsEAAAAFAAAAAAAAAAAAAAAFjpHYd/1EHcKjXtG9rJrSEYUAAAAGAAAAAAAAAAAAAAAG+H3ZKnXYnzCbGubBFIYwsToAAAAHAAAAAAAAAAAAAAAHRdZHflDxQqZ5gcAYLLK4x88AAAAIAAAAAAAAAAAAAAAIDGgugpHqWEvuS1wX14WgY8AAAAAJAAAAAAAAAAAAAAAJ3hyms3ACVxj2e+RfAho3yPEAAAAKAAAAAAAAAAAAAAAK0X/5CEzDLf70tbXyVnGjhYsAAAALAAAAAAAAAAAAAAALkcNpbmDmXRxE1hhRJ13DomEAAAAMAAAAAAAAAAAAAAAMyKPNYu6yDkTDN0fpmucqvkEAAAANAAAAAAAAAAAAAAANtPbs2QSYPiaofEWijkhH4l3/////AAAADgAAAAAAAAAAAAAADgAAAACOPBIHSKnA6R8pRzApQ4ph");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_NO_KDF hello small frames", "SGVsbG8sIHdvcmxkIQ==", "AYAAeK2rYVpanUbpZSQeXXCPSbUACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAgAAAAAMAAAAAgAAAAAAAAAAAAAAADIJySGWeCEKCF1KUDq80bkAAAABAAAAAAAAAAAAAAABYaRtUtoTkqcMtNWVfv9fd6+DAAAAAgAAAAAAAAAAAAAAAtJAmckb5stkVtx3CO+aVrKtkwAAAAMAAAAAAAAAAAAAAAPE4lbg99AfTgKpHyAoCYr0KzkAAAAEAAAAAAAAAAAAAAAE6EnuGyjqHEBoWwwRri6klC7KAAAABQAAAAAAAAAAAAAABY62LvtSnIpTBnFQMUhMms8HHgAAAAYAAAAAAAAAAAAAAAa4uS6sluyqe8OBzexfXZ28raL/////AAAABwAAAAAAAAAAAAAABwAAAAFEe6GTtWFXQpNGRfUH56QbtQ==");
    decrypt_test_vector(AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE, "ALG_AES_256_GCM_IV12_TAG16_NO_KDF hello unframed", "SGVsbG8sIHdvcmxkIQ==", "AYAAeAr8nRUGvvNNJX+9eVc6MYsACAABAAF4AAF5AAEACHplcm8ta2V5AA1wcm92aWRlciBpbmZvAAEAAQAAAAAMAAAAAAAAAAAAAAAAAAAAAFtdCKkG58xv1CAV/uK2QDMAAAAAAAAAAAAAAAEAAAAAAAAADWGkSE6bWkerxnIxxbDDFuvB4V9ED6fQkGBrO1Y3");

    return suite_failed;
}
