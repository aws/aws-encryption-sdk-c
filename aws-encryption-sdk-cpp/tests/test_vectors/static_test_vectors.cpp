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

#include <aws/core/Aws.h>
#include <aws/common/common.h>
#include <aws/common/error.h>
#include <aws/common/byte_buf.h>
#include <aws/common/encoding.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/raw_aes_keyring.h>
#include <aws/cryptosdk/raw_rsa_keyring.h>
#include <aws/cryptosdk/kms_keyring.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/session.h>

#include <json-c/json.h>
#include <json-c/json_object.h>

#include "testutil.h"

using namespace Aws::Cryptosdk;
using namespace std;
using Aws::SDKOptions;

int passed, failed, decrypt_false, aes_passed, rsa_passed, kms_passed, not_yet_supported;

static int strcmp_helper(json_object *jso, const char *str)
{
    const char *tmp_str = json_object_get_string(jso);
    return strcmp(tmp_str, str);
}

static int verify_manifest_type_and_version(json_object *manifest_obj)
{
    json_object *manifest_type_obj = NULL;
    json_object *manifest_version_obj = NULL;

    if (!json_object_object_get_ex(manifest_obj, "type", &manifest_type_obj))
        return AWS_OP_ERR;
    if (strcmp_helper(manifest_type_obj, "awses-decrypt") != 0)
        return AWS_OP_ERR;
    if (!json_object_object_get_ex(manifest_obj, "version", &manifest_version_obj))
        return AWS_OP_ERR;
    if (json_object_get_int(manifest_version_obj) != 1)
        return AWS_OP_ERR;

    return AWS_OP_SUCCESS;
}

static int verify_keys_manifest_type_and_version(json_object *keys_manifest_obj)
{
    json_object *keys_manifest_type_obj = NULL;
    json_object *keys_manifest_version_obj = NULL;

    if (!json_object_object_get_ex(keys_manifest_obj, "type", &keys_manifest_type_obj))
        return AWS_OP_ERR;
    if (strcmp_helper(keys_manifest_type_obj, "keys") != 0)
        return AWS_OP_ERR;
    if (!json_object_object_get_ex(keys_manifest_obj, "version", &keys_manifest_version_obj))
        return AWS_OP_ERR;
    if (json_object_get_int(keys_manifest_version_obj) != 3)
        return AWS_OP_ERR;

    return AWS_OP_SUCCESS;
}

static int get_base64_decoded_material(struct aws_allocator *alloc, struct aws_byte_buf *decoded_material, struct json_object *material_obj)
{
    size_t decoded_len = 0;
    const aws_byte_cursor in = aws_byte_cursor_from_c_str(json_object_get_string(material_obj));
    if (aws_base64_compute_decoded_len(&in, &decoded_len))
    {
        failed++;
        fprintf(stderr, "Failed to compute base64 decode length %d\n", aws_last_error());
        return AWS_OP_ERR;
    }
    if (aws_byte_buf_init(decoded_material, alloc, decoded_len + 2))
    {
        failed++;
        fprintf(stderr, "Failed to init aws_byte_buf %d\n", aws_last_error());
        return AWS_OP_ERR;
    }
    memset(decoded_material->buffer, 0xdd, decoded_material->capacity);
    decoded_material->len = 0;

    struct aws_byte_cursor encoded_material = aws_byte_cursor_from_c_str(json_object_get_string(material_obj));
    if (aws_base64_decode(&encoded_material, decoded_material))
    {
        failed++;
        fprintf(stderr, "Failed to base64 decode %d\n", aws_last_error());
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static enum aws_cryptosdk_rsa_padding_mode get_padding_mode(const char *padding_algorithm, const char *padding_hash)
{
    if (strcmp(padding_algorithm, "pkcs1") == 0)
    {
        return AWS_CRYPTOSDK_RSA_PKCS1;
    }
    else if (strcmp(padding_algorithm, "oaep-mgf1") == 0)
    {
        if (strcmp(padding_hash, "sha1") == 0)
        {
            return AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1;
        }
        else if (strcmp(padding_hash, "sha256") == 0)
        {
            return AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1;
        }
        else
        {
            /* The AWS Encryption SDK for C currently doesn't support SHA384 and SHA512 for 
               use with RSA OAEP wrapping algorithms. We will be adding support to this at a 
               later stage. For more information refer to issue #187. */
            not_yet_supported++;
            fprintf(stderr, "Padding mode not yet supported pending #187\n");
            return AWS_CRYPTOSDK_RSA_NOT_YET_IMPLEMENTED;
        }
    }
    else
    {
        failed++;
        fprintf(stderr, "Padding mode not supported by aws_encryption_sdk\n");
        return AWS_CRYPTOSDK_RSA_NOT_YET_IMPLEMENTED;
    }
}

static int process_test_scenarios(struct aws_allocator *alloc, std::string pt_filename, std::string ct_filename, json_object *master_keys_obj, json_object *keys_obj)
{
    json_object *key_type_obj = NULL;
    json_object *key_name_obj = NULL;
    json_object *provider_id_obj = NULL;
    json_object *encryption_algorithm_obj = NULL;
    json_object *key_category_obj = NULL;
    json_object *material_obj = NULL;
    json_object *encoding_obj = NULL;
    json_object *decrypt_obj = NULL;
    json_object *key_id_obj = NULL;

    for (int j = 0; j < json_object_array_length(master_keys_obj); j++)
    {
        struct aws_cryptosdk_keyring *kr = NULL;
        struct aws_cryptosdk_session *session = NULL;
        struct aws_cryptosdk_cmm *cmm = NULL;
        uint8_t *output_buffer = NULL;
        uint8_t *ciphertext = NULL;
        uint8_t *plaintext = NULL;
        size_t ct_len = 0;
        size_t pt_len = 0;
        size_t out_produced = 0;
        size_t in_consumed = 0;

        json_object *json_obj_mk_obj = json_object_array_get_idx(master_keys_obj, j);

        if (!json_object_object_get_ex(json_obj_mk_obj, "type", &key_type_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
        if (!json_object_object_get_ex(json_obj_mk_obj, "key", &key_name_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

        json_object_object_get_ex(json_obj_mk_obj, "provider-id", &provider_id_obj);
        json_object_object_get_ex(json_obj_mk_obj, "encryption-algorithm", &encryption_algorithm_obj);
        json_object_object_get_ex(keys_obj, json_object_get_string(key_name_obj), &key_category_obj);
        json_object_object_get_ex(key_category_obj, "material", &material_obj);
        json_object_object_get_ex(key_category_obj, "encoding", &encoding_obj);

        if (!json_object_object_get_ex(key_category_obj, "key-id", &key_id_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

        if (!json_object_object_get_ex(key_category_obj, "decrypt", &decrypt_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);   
        /* If the decrypt attribute in the keys manifest is set to false, the corresponding key
           cannot be used to decrypt. In this case, we simply mark the test as passed and skip 
           to the next test case scenario. */
        if (strcmp_helper(decrypt_obj, "false") == 0)
        {
            passed++;
            decrypt_false++;
            goto next_test_scenario;
        }

        if (strcmp_helper(key_type_obj, "raw") == 0)
        {
            if (strcmp_helper(encryption_algorithm_obj, "aes") == 0)
            {
                if (!material_obj)
                {
                    failed++;
                    fprintf(stderr, "Failed to obtain the raw key material %d\n", aws_last_error());
                    goto next_test_scenario;
                }

                if (strcmp_helper(encoding_obj, "base64") != 0)
                    return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

                struct aws_byte_buf decoded_material;

                if (get_base64_decoded_material(alloc, &decoded_material, material_obj))
                    return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

                //setup of aes keyring
                if (!(kr = aws_cryptosdk_raw_aes_keyring_new(alloc,
                                                             (const uint8_t *)json_object_get_string(key_id_obj), strlen(json_object_get_string(key_id_obj)),
                                                             (const uint8_t *)json_object_get_string(provider_id_obj), strlen(json_object_get_string(provider_id_obj)),
                                                             decoded_material.buffer, (enum aws_cryptosdk_aes_key_len)decoded_material.len)))
                {
                    failed++;
                    fprintf(stderr, "Failed to initialize aws_cryptosdk_raw_aes_keyring %d\n", aws_last_error());
                    goto next_test_scenario;
                }
            }
            else if (strcmp_helper(encryption_algorithm_obj, "rsa") == 0)
            {
                //setup of rsa keyring
                if (!material_obj)
                {
                    failed++;
                    fprintf(stderr, "Failed to obtain the raw key material %d\n", aws_last_error());
                    goto next_test_scenario;
                }
                const char *pem_file = json_object_get_string(material_obj);
                if (strcmp_helper(encoding_obj, "pem") != 0)
                {
                    return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
                }
                json_object *padding_algorithm_obj = NULL, *padding_hash_obj = NULL;

                json_object_object_get_ex(json_obj_mk_obj, "padding-algorithm", &padding_algorithm_obj);
                const char *padding_algorithm = json_object_get_string(padding_algorithm_obj);
                if (!padding_algorithm)
                    return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

                json_object_object_get_ex(json_obj_mk_obj, "padding-hash", &padding_hash_obj);
                const char *padding_hash = json_object_get_string(padding_hash_obj);

                enum aws_cryptosdk_rsa_padding_mode padding_mode = get_padding_mode(padding_algorithm, padding_hash);
                if (padding_mode == AWS_CRYPTOSDK_RSA_NOT_YET_IMPLEMENTED)
                    goto next_test_scenario;

                if (!(kr = aws_cryptosdk_raw_rsa_keyring_new(alloc,
                                                             (const uint8_t *)json_object_get_string(key_id_obj), strlen(json_object_get_string(key_id_obj)),
                                                             (const uint8_t *)json_object_get_string(provider_id_obj), strlen(json_object_get_string(provider_id_obj)),
                                                             pem_file, NULL, padding_mode)))
                {
                    failed++;
                    fprintf(stderr, "Failed to initialize aws_cryptosdk_raw_rsa_keyring %d\n", aws_last_error());
                    goto next_test_scenario;
                }
            }
        }
        else
        {
            //setup of kms keyring
            if (!key_id_obj)
            {
                failed++;
                fprintf(stderr, "Failed to obtain the kms_key_id %d\n", aws_last_error());
                goto next_test_scenario;
            }
            const Aws::String key_id = json_object_get_string(key_id_obj);
            kr = KmsKeyring::Builder().Build({key_id});
            if (!kr)
            {
                fprintf(stderr, "Failed to initialize aws_cryptosdk_kms_keyring %d\n", aws_last_error());
                goto next_test_scenario;
            }
        }

        if (!(cmm = aws_cryptosdk_default_cmm_new(alloc, kr)))
        {
            failed++;
            fprintf(stderr, "Failed to initialize aws_cryptosdk_default_cmm %d\n", aws_last_error());
            goto next_test_scenario;
        }

        if (!(session = aws_cryptosdk_session_new_from_cmm(alloc, AWS_CRYPTOSDK_DECRYPT, cmm)))
        {
            failed++;
            fprintf(stderr, "Failed to initialize aws_cryptosdk_session %d\n", aws_last_error());
            goto next_test_scenario;
        }

        if (test_loadfile(ct_filename.c_str(), &ciphertext, &ct_len))
        {
            failed++;
            fprintf(stderr, "Failed to load ciphertext file %s: %d\n", ct_filename.c_str(), aws_last_error());
            goto next_test_scenario;
        }

        if (test_loadfile(pt_filename.c_str(), &plaintext, &pt_len))
        {
            failed++;
            fprintf(stderr, "Failed to load plaintext file %s: %d\n", pt_filename.c_str(), aws_last_error());
            goto next_test_scenario;
        }

        output_buffer = (uint8_t *)malloc(pt_len);
        if (!output_buffer)
        {
            failed++;
            fprintf(stderr, "out of memory\n");
            goto next_test_scenario;
        }

        if (aws_cryptosdk_session_process(session, output_buffer, pt_len, &out_produced, ciphertext, ct_len, &in_consumed) != AWS_OP_SUCCESS)
        {
            failed++;
            goto next_test_scenario;
        }

        if (pt_len != out_produced)
        {
            failed++;
            fprintf(stderr, "Wrong output size, PlainText length = %zu, Produced output length = %zu %d\n", pt_len, out_produced, aws_last_error());
            goto next_test_scenario;
        }

        if (memcmp(output_buffer, plaintext, pt_len))
        {
            failed++;
            fprintf(stderr, "Plaintext mismatch for test case %d\n", aws_last_error());
        }
        else
        {
            if (strcmp_helper(key_type_obj, "raw") == 0)
            {
                if (strcmp_helper(encryption_algorithm_obj, "rsa") == 0)
                    rsa_passed++;
                if (strcmp_helper(encryption_algorithm_obj, "aes") == 0)
                    aes_passed++;
            }

            if (strcmp_helper(key_type_obj, "aws-kms") == 0)
                kms_passed++;
            passed++;
        }

    next_test_scenario:
        if (output_buffer) free(output_buffer);
        if (ciphertext) free(ciphertext);
        if (plaintext) free(plaintext);
        if (session) aws_cryptosdk_session_destroy(session);
        if (cmm) aws_cryptosdk_cmm_release(cmm);
        if (kr) aws_cryptosdk_keyring_release(kr);
    }
    return AWS_OP_SUCCESS;
}

static int test_vector_runner(const char *path)
{
    char manifest_filename[100];
    char *key;

    struct json_object *val;
    struct lh_entry *entry;
    struct aws_allocator *alloc = aws_default_allocator();

    json_object *manifest_obj = NULL;
    json_object *tests_obj = NULL;
    json_object *keys_obj = NULL;
    json_object *test_case_obj = NULL;
    json_object *pt_filename_obj = NULL;
    json_object *ct_filename_obj = NULL;
    json_object *master_keys_obj = NULL;
    json_object *keys_manifest_obj = NULL;

    strcpy(manifest_filename, path);
    strcat(manifest_filename, "/manifest.json");
    json_object *manifest_jso_obj = json_object_from_file(manifest_filename);

    if (!json_object_object_get_ex(manifest_jso_obj, "manifest", &manifest_obj))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    if (verify_manifest_type_and_version(manifest_obj))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    if (!json_object_object_get_ex(manifest_jso_obj, "tests", &tests_obj))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    /* I am looking for suggestions to replace the "file:/" string in the ciphertext and plaintext filenames 
    from the manifest file with the relative path detected, in a way that is compatible for all platforms. 
    Leaving this as a temporary work-around for now.*/

    std::string find_str = "file:/";

    if (!json_object_object_get_ex(manifest_jso_obj, "keys", &keys_obj))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    std::string keys_filename = json_object_get_string(keys_obj);
    keys_filename.replace(keys_filename.find(find_str), find_str.length(), path);

    json_object *keys_manifest_jso_obj = json_object_from_file(keys_filename.c_str());
    if (!json_object_object_get_ex(keys_manifest_jso_obj, "keys", &keys_obj))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    if (!json_object_object_get_ex(keys_manifest_jso_obj, "manifest", &keys_manifest_obj))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    if (verify_keys_manifest_type_and_version(keys_manifest_obj))
        return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

    for (entry = json_object_get_object(tests_obj)->head; (entry ? (key = (char *)entry->k, val = (struct json_object *)entry->v, entry) : 0); entry = entry->next)
    {
        if (!json_object_object_get_ex(tests_obj, key, &test_case_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
        if (!json_object_object_get_ex(val, "plaintext", &pt_filename_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
        if (!json_object_object_get_ex(val, "ciphertext", &ct_filename_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

        std::string pt_filename = json_object_get_string(pt_filename_obj);
        std::string ct_filename = json_object_get_string(ct_filename_obj);

        pt_filename.replace(pt_filename.find(find_str), find_str.length(), path);
        ct_filename.replace(ct_filename.find(find_str), find_str.length(), path);

        if (!json_object_object_get_ex(val, "master-keys", &master_keys_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);

        if (process_test_scenarios(alloc, pt_filename, ct_filename, master_keys_obj, keys_obj))
            return aws_raise_error(AWS_CRYPTOSDK_ERR_BAD_STATE);
    }
    printf("Decryption successfully completed for %d test cases and failed for %d.\n", passed, failed);
    printf("AES Passed = %d, RSA Passed = %d, KMS Passed = %d, Encrypt-only = %d, Not-yet-supported = %d.\n",
           aes_passed, rsa_passed, kms_passed, decrypt_false, not_yet_supported);
    return AWS_OP_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Wrong number of arguments\nUsage: ./static_test_vectors /path/to/manifest/files\n");
        return EXIT_FAILURE;
    }
    aws_load_error_strings();
    aws_cryptosdk_load_error_strings();
    SDKOptions options;
    Aws::InitAPI(options);
    test_vector_runner(argv[1]);
    Aws::ShutdownAPI(options);
    return EXIT_SUCCESS;
}
