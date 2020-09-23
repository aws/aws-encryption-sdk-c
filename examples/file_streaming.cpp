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

#include <aws/core/Aws.h>

#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/session.h>

/* Encrypts or decrypts a file in a streaming way. This is suitable
 * for large files that cannot be held in a single memory buffer.
 */
static int process_file(
    char const *output_filename,
    char const *input_filename,
    aws_cryptosdk_mode mode,
    char const *key_arn,
    struct aws_allocator *allocator) {
    FILE *input_fp = fopen(input_filename, "rb");
    if (!input_fp) {
        fprintf(stderr, "Could not open input file %s for reading; error %s\n", input_filename, strerror(errno));
        return -1;
    }

    FILE *output_fp = fopen(output_filename, "wb");
    if (!output_fp) {
        fprintf(
            stderr,
            "Could not open output file %s for writing plaintext; error %s\n",
            output_filename,
            strerror(errno));
        fclose(input_fp);
        return -1;
    }

    /* Initialize a KMS keyring using the provided ARN. */
    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build(key_arn);

    /* Initialize the session object. */
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_keyring_2(allocator, mode, kms_keyring);
    if (!session) abort();

    if (aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT)) {
        fprintf(stderr, "set_commitment_policy failed: %s", aws_error_debug_str(aws_last_error()));
        abort();
    }

    /* Since the session now holds a reference to the keyring, we can release the local reference. */
    aws_cryptosdk_keyring_release(kms_keyring);

    /* Allocate buffers for input and output.  Note that the initial size is not critical, as we will resize
     * and reallocate if more space is needed to make progress.
     */
    const size_t INITIAL_CAPACITY = 16 * 1024;

    uint8_t *input_buffer = (uint8_t *)malloc(INITIAL_CAPACITY);
    size_t input_capacity = INITIAL_CAPACITY;
    size_t input_len      = 0;

    uint8_t *output_buffer = (uint8_t *)malloc(INITIAL_CAPACITY);
    size_t output_capacity = INITIAL_CAPACITY;

    /* These variables keep a running total of the number of bytes of input consumed and output produced,
     * while the similarly named variables without "total_" measure the bytes consumed and produced in
     * a single iteration of the loop.
     */
    size_t total_input_consumed  = 0;
    size_t total_output_produced = 0;

    int aws_status;
    while (!aws_cryptosdk_session_is_done(session)) {
        if (!feof(input_fp) && (input_len < input_capacity)) {
            size_t num_read = fread(&input_buffer[input_len], 1, input_capacity - input_len, input_fp);
            if (ferror(input_fp)) abort();
            input_len += num_read;
        }

        /* During encryption, once we know exactly how much plaintext is to be consumed, we call the
         * set_message_size() function with the exact input size so that the session can be finished.
         */
        if ((mode == AWS_CRYPTOSDK_ENCRYPT) && feof(input_fp)) {
            aws_status = aws_cryptosdk_session_set_message_size(session, total_input_consumed + input_len);
            if (aws_status) break;
        }

        size_t output_produced, input_consumed;
        aws_status = aws_cryptosdk_session_process(
            session, output_buffer, output_capacity, &output_produced, input_buffer, input_len, &input_consumed);
        if (aws_status) break;
        total_input_consumed += input_consumed;

        if ((input_consumed > 0) && (input_consumed < input_len)) {
            /* If not all input was consumed, move what's left over to the beginning of the buffer. */
            memmove(input_buffer, &input_buffer[input_consumed], input_len - input_consumed);
        }
        input_len -= input_consumed;

        if (output_produced > 0) {
            size_t num_written = fwrite(output_buffer, 1, output_produced, output_fp);
            if (ferror(output_fp)) abort();

            if (num_written != output_produced) abort();
            total_output_produced += num_written;
        }

        /* Determine how much buffer space we need to make progress, and resize buffers if necessary. */
        size_t input_needed, output_needed;
        aws_cryptosdk_session_estimate_buf(session, &output_needed, &input_needed);

        if (!input_consumed && !output_produced && input_capacity >= input_needed && output_capacity >= output_needed) {
            /* This should be impossible. */
            fprintf(
                stderr, "Unexpected error: Encryption SDK made no progress.  Please contact the development team.\n");
            abort();
        }

        if (output_capacity < output_needed) {
            output_buffer = (uint8_t *)realloc(output_buffer, output_needed);
            if (!output_buffer) abort();
            output_capacity = output_needed;
        }
        if (input_capacity < input_needed) {
            input_buffer = (uint8_t *)realloc(input_buffer, input_needed);
            if (!input_buffer) abort();
            input_capacity = input_needed;
        }
    }

    if (aws_status) {
        fprintf(
            stderr,
            "%s failed with error %d: %s\n",
            (mode == AWS_CRYPTOSDK_ENCRYPT) ? "Encryption" : "Decryption",
            aws_last_error(),
            aws_error_debug_str(aws_last_error()));
    } else {
        printf(
            "%s succeeded; %zu input bytes consumed from %s; %zu output bytes written to %s\n",
            (mode == AWS_CRYPTOSDK_ENCRYPT) ? "Encryption" : "Decryption",
            total_input_consumed,
            input_filename,
            total_output_produced,
            output_filename);
    }

    free(input_buffer);
    free(output_buffer);
    fclose(input_fp);
    fclose(output_fp);

    aws_cryptosdk_session_destroy(session);
    return aws_status;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(
            stderr,
            "Usage: %s <key_arn> <input_filename>\n"
            "Encrypts <input_filename> to <input_filename>.encrypted and\n"
            "decrypts it to <input_filename>.decrypted\n",
            argv[0]);
        exit(1);
    }

    char const *key_arn        = argv[1];
    char const *input_filename = argv[2];

    size_t filename_len      = strlen(input_filename) + 11;
    char *encrypted_filename = (char *)malloc(filename_len);
    char *decrypted_filename = (char *)malloc(filename_len);
    if (!encrypted_filename || !decrypted_filename) abort();

    snprintf(encrypted_filename, filename_len, "%s.encrypted", input_filename);
    snprintf(decrypted_filename, filename_len, "%s.decrypted", input_filename);

    aws_common_library_init(aws_default_allocator());
    aws_cryptosdk_load_error_strings();

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    struct aws_allocator *allocator = aws_default_allocator();

    // Encrypt the file, and if that succeeds decrypt it too.
    int ret = process_file(encrypted_filename, input_filename, AWS_CRYPTOSDK_ENCRYPT, key_arn, allocator);

    if (!ret) {
        ret = process_file(decrypted_filename, encrypted_filename, AWS_CRYPTOSDK_DECRYPT, key_arn, allocator);
    }

    Aws::ShutdownAPI(options);

    free(encrypted_filename);
    free(decrypted_filename);
    return ret;
}
