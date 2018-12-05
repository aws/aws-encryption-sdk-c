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
#include <unistd.h>

#include <aws/core/Aws.h>

#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/session.h>
#include <aws/cryptosdk/kms_keyring.h>

#include <aws/core/client/ClientConfiguration.h>

const char *KEY_ARN = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";
const size_t INITIAL_CAPACITY = 16 * 1024;

static void resize_buffer(aws_byte_buf * buffer, size_t desired_capacity) {
    if (buffer->capacity < desired_capacity) {
        aws_byte_buf old_buf = *buffer;
        aws_byte_cursor cursor = aws_byte_cursor_from_buf(&old_buf);       
        aws_byte_buf_init(buffer, old_buf.allocator, desired_capacity);
        int status = aws_byte_buf_append(buffer, &cursor);
        aws_byte_buf_clean_up_secure(&old_buf);
        if (status != AWS_OP_SUCCESS) abort();
    }
}

static void process_file(FILE * output_fp, FILE * input_fp, aws_cryptosdk_mode mode, aws_allocator * allocator) {
    auto kms_keyring = Aws::Cryptosdk::KmsKeyring::Builder().Build({KEY_ARN});

    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(allocator, kms_keyring);
    if (!cmm) abort();
    aws_cryptosdk_keyring_release(kms_keyring);

    struct aws_cryptosdk_session *session = aws_cryptosdk_session_new_from_cmm(allocator, mode, cmm);
    if (!session) abort();
    aws_cryptosdk_cmm_release(cmm);

    aws_byte_buf input_buffer, output_buffer;
    int aws_status = aws_byte_buf_init(&input_buffer, allocator, INITIAL_CAPACITY);
    if (aws_status != AWS_OP_SUCCESS) abort();

    aws_status = aws_byte_buf_init(&output_buffer, allocator, INITIAL_CAPACITY);
    if (aws_status != AWS_OP_SUCCESS) abort();

    size_t total_input_consumed = 0;
    size_t total_output_produced = 0;

    while (!aws_cryptosdk_session_is_done(session)) {
        if (!feof(input_fp) && (input_buffer.len < input_buffer.capacity)) {
            size_t num_read = fread(&input_buffer.buffer[input_buffer.len], 1, input_buffer.capacity - input_buffer.len,
                                    input_fp);
            if (ferror(input_fp)) break;
            assert(num_read >= 0);
            input_buffer.len += num_read;
        }

        if ((mode == AWS_CRYPTOSDK_ENCRYPT) && feof(input_fp)) {
            // During encryption, once end of the file is reached, set message size so session can be finished
            aws_status = aws_cryptosdk_session_set_message_size(session, total_input_consumed + input_buffer.len);
            if (aws_status != AWS_OP_SUCCESS) break;
        }

        size_t output_done, input_done;
        aws_status = aws_cryptosdk_session_process(session, output_buffer.buffer, output_buffer.capacity, &output_done,
                                                   input_buffer.buffer, input_buffer.len, &input_done);
        if (aws_status != AWS_OP_SUCCESS) break;
        total_input_consumed += input_done;

        if (input_done < input_buffer.len) {
            // If not all input was consumed, move what's left over to the beginning of the buffer
            memmove(input_buffer.buffer, &input_buffer.buffer[input_done], input_buffer.len - input_done);
        }
        input_buffer.len -= input_done;

        if (output_done > 0) {
            size_t num_written = fwrite(output_buffer.buffer, 1, output_done, output_fp);
            if (ferror(output_fp)) break;

            if (num_written != output_done) abort();
            total_output_produced += num_written;
        }

        // Determine how much buffer space we need to make progress, and resize if necessary
        size_t input_needed, output_needed;
        aws_cryptosdk_session_estimate_buf(session, &output_needed, &input_needed);

        resize_buffer(&output_buffer, output_needed);
        resize_buffer(&input_buffer, input_needed);
    }

    if (!aws_cryptosdk_session_is_done(session)) {
        printf("Processing failed; status %s errno %s\n", aws_error_str(aws_status), strerror(errno));
    } else {
        printf("Processing succeeded; %d input bytes were consumed; %d output bytes were produced\n",
               (int)total_input_consumed, (int)total_output_produced) ;
    }

    aws_byte_buf_clean_up_secure(&input_buffer);
    aws_byte_buf_clean_up_secure(&output_buffer);
    aws_cryptosdk_session_destroy(session);
}

void encrypt_file(FILE * ciphertext_fp, FILE * plaintext_fp, struct aws_allocator * allocator) {
    process_file(ciphertext_fp, plaintext_fp, AWS_CRYPTOSDK_ENCRYPT, allocator);
}

void decrypt_file(FILE * plaintext_fp, FILE * ciphertext_fp, struct aws_allocator * allocator) {
    process_file(plaintext_fp, ciphertext_fp, AWS_CRYPTOSDK_DECRYPT, allocator);
}

int main(int argc, char * argv[]) {
    if ((argc != 4) || (strcmp(argv[1], "-e") && strcmp(argv[1], "-d"))) {
        fprintf(stderr, "Usage: %s [-e|-d] <input_file> <output_file>\n", argv[0]);
        exit(1);
    }

    bool do_encrypt = !strcmp(argv[1], "-e");

    FILE * input_fp = fopen(argv[2], "r");
    if (!input_fp) {
        fprintf(stderr, "Could not open input file %s for reading; error %s\n", argv[2], strerror(errno));
        exit(1);
    }

    FILE * output_fp = fopen(argv[3], "w");
    if (!output_fp) {
        fprintf(stderr, "Could not open output file %s for writing; error %s\n", argv[3], strerror(errno));
        fclose(input_fp);
        exit(1);
    }

    aws_cryptosdk_load_error_strings();

    Aws::SDKOptions::SDKOptions options;
    Aws::InitAPI(options);
    enum { BUFFER_SIZE = 1024 };

    struct aws_allocator * allocator = aws_default_allocator();

    if (do_encrypt) {
        encrypt_file(output_fp, input_fp, allocator);
    } else {
        decrypt_file(output_fp, input_fp, allocator);
    }

    fclose(input_fp);
    fclose(output_fp);

    Aws::ShutdownAPI(options);

    return 0;
}
