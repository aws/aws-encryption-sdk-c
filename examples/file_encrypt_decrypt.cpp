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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <aws/core/Aws.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>

#include <aws/core/client/ClientConfiguration.h>

static void process_file(char const * output_filename,
                         char const * input_filename,
                         aws_cryptosdk_mode mode,
                         char const * key_arn,
                         struct aws_allocator * allocator) {
    FILE * input_fp = fopen(input_filename, "rb");
    if (!input_fp) {
        fprintf(stderr, "Could not open input file %s for reading; error %s\n", input_filename, strerror(errno));
        return;
    }

    FILE * output_fp = fopen(output_filename, "wb");
    if (!output_fp) {
        fprintf(stderr, "Could not open output file %s for writing plaintext; error %s\n", output_filename, strerror(errno));
        fclose(input_fp);
        return;
    }

    // Initialize a KMS keyring using the provided ARN.
    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build({key_arn});

    // Initialize the Cryptographic Materials Manager (CMM).
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(allocator, kms_keyring);
    if (!cmm) abort();
    // Since the CMM now holds a reference to the keyring, we can release the local reference.
    aws_cryptosdk_keyring_release(kms_keyring);

    // Initialize the session object.
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(allocator, mode, cmm);
    if (!session) abort();
    // Since the session now holds a reference to the CMM, we can release the local reference.
    aws_cryptosdk_cmm_release(cmm);

    // Allocate buffers for input and output.  Note that the initial size is not critical, as we will resize
    //   and reallocate if more space is needed to make progress.
    const size_t INITIAL_CAPACITY = 16 * 1024;

    uint8_t *input_buffer = (uint8_t *)malloc(INITIAL_CAPACITY);
    size_t input_capacity = INITIAL_CAPACITY;
    size_t input_len = 0;

    uint8_t *output_buffer = (uint8_t *)malloc(INITIAL_CAPACITY);
    size_t output_capacity = INITIAL_CAPACITY;
    size_t output_len = 0;

    // We use these variables to keep track of the number of bytes of input consumed and output generated.
    //   During encryption, once we know exactly how much plaintext is to be consumed, we call the
    //   set_message_size() function with the exact input size so that the session can be finished.
    size_t total_input_consumed = 0;
    size_t total_output_produced = 0;

    int aws_status = AWS_OP_SUCCESS;
    while (!aws_cryptosdk_session_is_done(session)) {
        if (!feof(input_fp) && (input_len < input_capacity)) {
            size_t num_read = fread(&input_buffer[input_len], 1, input_capacity - input_len,
                                    input_fp);
            if (ferror(input_fp)) abort();
            input_len += num_read;
        }

        if ((mode == AWS_CRYPTOSDK_ENCRYPT) && feof(input_fp)) {
            aws_status = aws_cryptosdk_session_set_message_size(session, total_input_consumed + input_len);
            if (aws_status) break;
        }

        size_t output_produced, input_consumed;
        aws_status = aws_cryptosdk_session_process(session, output_buffer, output_capacity, &output_produced,
                                                   input_buffer, input_len, &input_consumed);
        if (aws_status) break;
        total_input_consumed += input_consumed;

        if ((input_consumed > 0) && (input_consumed < input_len)) {
            // If not all input was consumed, move what's left over to the beginning of the buffer
            memmove(input_buffer, &input_buffer[input_consumed], input_len - input_consumed);
        }
        input_len -= input_consumed;

        if (output_produced > 0) {
            size_t num_written = fwrite(output_buffer, 1, output_produced, output_fp);
            if (ferror(output_fp)) abort();

            if (num_written != output_produced) abort();
            total_output_produced += num_written;
        }

        if (!input_consumed && !output_produced) { // We made no progress; something is wrong
            fprintf(stderr, "Unexpected error: encryption SDK made no progress.  Please contact the development team.\n");
            abort();
        }

        // Determine how much buffer space we need to make progress, and resize buffers if necessary
        size_t input_needed, output_needed;
        aws_cryptosdk_session_estimate_buf(session, &output_needed, &input_needed);

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
        fprintf(stderr, "%s failed with error %d: %s\n",
               (mode == AWS_CRYPTOSDK_ENCRYPT) ? "Encryption" : "Decryption",
               aws_last_error(),
               aws_error_debug_str(aws_last_error()));
    } else {
        printf("%s succeeded; %zu input bytes were consumed; %zu output bytes were produced\n",
               (mode == AWS_CRYPTOSDK_ENCRYPT) ? "Encryption" : "Decryption",
               total_input_consumed,
               total_output_produced) ;
    }

    free(input_buffer);
    free(output_buffer);
    fclose(input_fp);
    fclose(output_fp);

    aws_cryptosdk_session_destroy(session);
}

/*
 *  Usage
 *      $ file_encrypt_decrypt <key_arn> <input_filename>
 *  where
 *      <key_arn> is the ARN for a KMS key that will be used for encryption and decryption
 *      <input_filename> is the source file that will be encrypted and decrypted
 *  The program will encrypt the given <input_filename> and write the output to
 *      <input_filename>.encrypted
 *  It will then decrypt this file and write the output to
 *      <input_filename>.decrypted
 *
 */
int main(int argc, char * argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <key_arn> <input_filename>\n", argv[0]);
        exit(1);
    }

    char const * key_arn = argv[1];
    char const * input_filename = argv[2];

    char encrypted_filename[PATH_MAX];
    snprintf(encrypted_filename, sizeof(encrypted_filename), "%s.encrypted", input_filename);

    char decrypted_filename[PATH_MAX];
    snprintf(decrypted_filename, sizeof(decrypted_filename), "%s.decrypted", input_filename);

    aws_cryptosdk_load_error_strings();

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    struct aws_allocator * allocator = aws_default_allocator();

    // Encrypt file
    process_file(encrypted_filename, input_filename, AWS_CRYPTOSDK_ENCRYPT, key_arn, allocator);

    // Decrypt file
    process_file(decrypted_filename, encrypted_filename, AWS_CRYPTOSDK_DECRYPT, key_arn, allocator);

    Aws::ShutdownAPI(options);

    return 0;
}
