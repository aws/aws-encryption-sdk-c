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
#include <aws/cryptosdk/kms_keyring.h>

#include <aws/core/client/ClientConfiguration.h>

static void resize_buffer(uint8_t ** buffer, size_t desired_capacity, size_t current_capacity, struct aws_allocator * allocator) {
    int status = aws_mem_realloc(allocator, (void **)buffer, current_capacity, desired_capacity);
    if (status != AWS_OP_SUCCESS) abort();
}

static void process_file(FILE * output_fp, FILE * input_fp, aws_cryptosdk_mode mode, char const * key_arn, struct aws_allocator * allocator) {
    // Initialize a KMS keyring using the provided ARN.
    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build({key_arn});

    // Initialize the Cryptographic Materials Manager (CMM).  Note that since the CMM holds a
    //   reference to the keyring, we can release the local reference.
    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(allocator, kms_keyring);
    if (!cmm) abort();
    aws_cryptosdk_keyring_release(kms_keyring);

    // Initialize the session object.  Note that since the session holds a
    //   reference to the CMM, we can release the local reference.
    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(allocator, mode, cmm);
    if (!session) abort();
    aws_cryptosdk_cmm_release(cmm);

    // Allocate buffers for input and output.  Note that the initial size is not critical, as we will resize
    //   and reallocate if more space is needed to make progress.
    const size_t INITIAL_CAPACITY = 16 * 1024;

    uint8_t *input_buffer = (uint8_t *)aws_mem_acquire(allocator, INITIAL_CAPACITY);
    size_t input_capacity = INITIAL_CAPACITY;
    size_t input_len = 0;

    uint8_t *output_buffer = (uint8_t *)aws_mem_acquire(allocator, INITIAL_CAPACITY);
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
            if (ferror(input_fp)) break;
            assert(num_read >= 0);
            input_len += num_read;
        }

        if ((mode == AWS_CRYPTOSDK_ENCRYPT) && feof(input_fp)) {
            aws_status = aws_cryptosdk_session_set_message_size(session, total_input_consumed + input_len);
            if (aws_status != AWS_OP_SUCCESS) break;
        }

        size_t output_done, input_done;
        aws_status = aws_cryptosdk_session_process(session, output_buffer, output_capacity, &output_done,
                                                   input_buffer, input_len, &input_done);
        if (aws_status != AWS_OP_SUCCESS) break;
        total_input_consumed += input_done;

        if ((input_done > 0) && (input_done < input_len)) {
            // If not all input was consumed, move what's left over to the beginning of the buffer
            memmove(input_buffer, &input_buffer[input_done], input_len - input_done);
        }
        input_len -= input_done;

        if (output_done > 0) {
            size_t num_written = fwrite(output_buffer, 1, output_done, output_fp);
            if (ferror(output_fp)) break;

            if (num_written != output_done) abort();
            total_output_produced += num_written;
        }

        if (!input_done && !output_done) { // We made no progress; something is wrong
            break;
        }

        // Determine how much buffer space we need to make progress, and resize buffers if necessary
        size_t input_needed, output_needed;
        aws_cryptosdk_session_estimate_buf(session, &output_needed, &input_needed);

        if (output_capacity < output_needed) {
            resize_buffer(&output_buffer, output_needed, output_capacity, allocator);
            output_capacity = output_needed;
        }
        if (input_capacity < input_needed) {
            resize_buffer(&input_buffer, input_needed, input_capacity, allocator);
            input_capacity = input_needed;
        }
    }

    const char * processing_type = (mode == AWS_CRYPTOSDK_ENCRYPT) ? "Encryption" : "Decryption";
    if (!aws_cryptosdk_session_is_done(session)) {
        printf("%s failed; status %s errno %s\n", processing_type, aws_error_str(aws_status), strerror(errno));
    } else {
        printf("%s succeeded; %d input bytes were consumed; %d output bytes were produced\n",
               processing_type, (int)total_input_consumed, (int)total_output_produced) ;
    }

    aws_mem_release(allocator, input_buffer);
    aws_mem_release(allocator, output_buffer);

    aws_cryptosdk_session_destroy(session);
}

void encrypt_file(FILE * ciphertext_fp, FILE * plaintext_fp, char const * key_arn, struct aws_allocator * allocator) {
    process_file(ciphertext_fp, plaintext_fp, AWS_CRYPTOSDK_ENCRYPT, key_arn, allocator);
}

void decrypt_file(FILE * plaintext_fp, FILE * ciphertext_fp, char const * key_arn, struct aws_allocator * allocator) {
    process_file(plaintext_fp, ciphertext_fp, AWS_CRYPTOSDK_DECRYPT, key_arn, allocator);
}

int main(int argc, char * argv[]) {
    if ((argc != 5) || (strcmp(argv[1], "-e") && strcmp(argv[1], "-d"))) {
        fprintf(stderr, "Usage: %s [-e|-d] <key_arn> <input_file> <output_file>\n", argv[0]);
        exit(1);
    }

    bool do_encrypt = !strcmp(argv[1], "-e");

    char const * key_arn = argv[2];

    FILE * input_fp = fopen(argv[3], "rb");
    if (!input_fp) {
        fprintf(stderr, "Could not open input file %s for reading; error %s\n", argv[2], strerror(errno));
        exit(1);
    }

    FILE * output_fp = fopen(argv[4], "wb");
    if (!output_fp) {
        fprintf(stderr, "Could not open output file %s for writing; error %s\n", argv[3], strerror(errno));
        fclose(input_fp);
        exit(1);
    }

    aws_cryptosdk_load_error_strings();

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    struct aws_allocator * allocator = aws_default_allocator();

    if (do_encrypt) {
        encrypt_file(output_fp, input_fp, key_arn, allocator);
    } else {
        decrypt_file(output_fp, input_fp, key_arn, allocator);
    }

    fclose(input_fp);
    fclose(output_fp);

    Aws::ShutdownAPI(options);

    return 0;
}
