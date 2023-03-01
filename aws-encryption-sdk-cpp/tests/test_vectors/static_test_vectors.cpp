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

#include <aws/common/byte_buf.h>
#include <aws/common/common.h>
#include <aws/common/encoding.h>
#include <aws/common/error.h>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/cryptosdk/cpp/kms_keyring.h>
#include <aws/cryptosdk/cpp/kms_mrk_keyring.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/error.h>
#include <aws/cryptosdk/materials.h>
#include <aws/cryptosdk/multi_keyring.h>
#include <aws/cryptosdk/raw_aes_keyring.h>
#include <aws/cryptosdk/raw_rsa_keyring.h>
#include <aws/cryptosdk/session.h>

#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>

#include <json-c/json.h>
#include <json-c/json_object.h>
#include <unistd.h>

#include "credential_reusing_client_supplier.h"
#include "testing.h"
#include "testutil.h"

#define MANIFEST_VERSION 2
#define KEYS_MANIFEST_VERSION 3

using namespace Aws::Cryptosdk;
using namespace std;
using Aws::SDKOptions;

#define TEST_VECTORS_TAG "static_test_vectors"

enum test_type {
    AWS_CRYPTOSDK_AES,
    AWS_CRYPTOSDK_RSA,
    AWS_CRYPTOSDK_KMS,
    AWS_CRYPTOSDK_KMS_MRK_AWARE,
    AWS_CRYPTOSDK_KMS_MRK_AWARE_DISCOVERY
};

struct expected_outcome {
    bool success;
    std::string pt_filename;  // only meaningful if success
    std::string error_desc;   // only meaningful if !success
};

int passed, failed, encrypt_only, not_yet_supported, test_type_passed[5];

static int cmp_jsonstr_with_cstr(json_object *jso, const char *str) {
    const char *tmp_str = json_object_get_string(jso);
    return strcmp(tmp_str, str);
}

static int verify_manifest_type_and_version(json_object *manifest_obj) {
    json_object *manifest_type_obj    = NULL;
    json_object *manifest_version_obj = NULL;

    if (!json_object_object_get_ex(manifest_obj, "type", &manifest_type_obj)) return AWS_OP_ERR;
    if (cmp_jsonstr_with_cstr(manifest_type_obj, "awses-decrypt")) return AWS_OP_ERR;
    if (!json_object_object_get_ex(manifest_obj, "version", &manifest_version_obj)) return AWS_OP_ERR;
    if (json_object_get_int(manifest_version_obj) != MANIFEST_VERSION) return AWS_OP_ERR;

    return AWS_OP_SUCCESS;
}

static int verify_keys_manifest_type_and_version(json_object *keys_manifest_obj) {
    json_object *keys_manifest_type_obj    = NULL;
    json_object *keys_manifest_version_obj = NULL;

    if (!json_object_object_get_ex(keys_manifest_obj, "type", &keys_manifest_type_obj)) return AWS_OP_ERR;
    if (cmp_jsonstr_with_cstr(keys_manifest_type_obj, "keys")) return AWS_OP_ERR;
    if (!json_object_object_get_ex(keys_manifest_obj, "version", &keys_manifest_version_obj)) return AWS_OP_ERR;
    if (json_object_get_int(keys_manifest_version_obj) != KEYS_MANIFEST_VERSION) return AWS_OP_ERR;

    return AWS_OP_SUCCESS;
}

static int get_base64_decoded_material(
    struct aws_allocator *alloc, struct aws_byte_buf *decoded_material, struct json_object *material_obj) {
    size_t decoded_len       = 0;
    const aws_byte_cursor in = aws_byte_cursor_from_c_str(json_object_get_string(material_obj));
    if (aws_base64_compute_decoded_len(&in, &decoded_len)) {
        return AWS_OP_ERR;
    }
    if (aws_byte_buf_init(decoded_material, alloc, decoded_len + 2)) {
        abort();
    }
    decoded_material->len = 0;

    struct aws_byte_cursor encoded_material = aws_byte_cursor_from_c_str(json_object_get_string(material_obj));
    if (aws_base64_decode(&encoded_material, decoded_material)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static bool get_padding_mode(
    enum aws_cryptosdk_rsa_padding_mode *rsa_padding_mode, const char *padding_algorithm, const char *padding_hash) {
    enum aws_cryptosdk_rsa_padding_mode padding_mode;
    if (!strcmp(padding_algorithm, "pkcs1")) {
        padding_mode = AWS_CRYPTOSDK_RSA_PKCS1;
    } else if (!strcmp(padding_algorithm, "oaep-mgf1")) {
        if (!strcmp(padding_hash, "sha1")) {
            padding_mode = AWS_CRYPTOSDK_RSA_OAEP_SHA1_MGF1;
        } else if (!strcmp(padding_hash, "sha256")) {
            padding_mode = AWS_CRYPTOSDK_RSA_OAEP_SHA256_MGF1;
        } else {
            /* The AWS Encryption SDK for C currently doesn't support SHA384 and SHA512 for
               use with RSA OAEP wrapping algorithms. We will be adding support to this at a
               later stage. For more information refer to issue #187. */
            fprintf(stderr, "Padding mode not yet supported pending #187\n");
            return false;
        }
    } else {
        fprintf(stderr, "Padding mode not supported by aws_encryption_sdk\n");
        return false;
    }
    *rsa_padding_mode = padding_mode;
    return true;
}

static shared_ptr<KmsKeyring::DiscoveryFilter> get_discovery_filter(struct json_object *discovery_filter_obj) {
    json_object *partition_obj = NULL;
    json_object_object_get_ex(discovery_filter_obj, "partition", &partition_obj);
    if (!partition_obj) {
        return nullptr;
    }

    KmsKeyring::DiscoveryFilterBuilder builder(json_object_get_string(partition_obj));

    json_object *account_ids_obj = NULL;
    json_object_object_get_ex(discovery_filter_obj, "account-ids", &account_ids_obj);
    if (!account_ids_obj) {
        return nullptr;
    }

    int arraylen = json_object_array_length(account_ids_obj);
    json_object *account_id_obj;
    for (int i = 0; i < arraylen; i++) {
        account_id_obj = json_object_array_get_idx(account_ids_obj, i);
        builder.AddAccount(json_object_get_string(account_id_obj));
    }

    return builder.Build();
}

static aws_cryptosdk_keyring *keyring_for_master_key_spec(
    struct aws_allocator *alloc,
    json_object *json_obj_mk_obj,
    json_object *keys_obj,
    enum test_type &test_type_idx,
    bool &not_supported,
    const shared_ptr<KmsKeyring::ClientSupplier> &client_supplier) {
    json_object *key_type_obj             = NULL;
    json_object *key_obj                  = NULL;
    json_object *provider_id_obj          = NULL;
    json_object *encryption_algorithm_obj = NULL;
    json_object *key_category_obj         = NULL;
    json_object *material_obj             = NULL;
    json_object *encoding_obj             = NULL;
    json_object *decrypt_obj              = NULL;
    json_object *key_id_obj               = NULL;

    aws_string *key_namespace = NULL;
    aws_string *key_name      = NULL;
    aws_string *region        = NULL;

    struct aws_cryptosdk_keyring *kr = NULL;
    not_supported                    = false;

    if (!json_object_object_get_ex(json_obj_mk_obj, "type", &key_type_obj)) {
        fprintf(stderr, "Failed to obtain master-key type\n");
        goto next_test_scenario;
    }
    if (json_object_object_get_ex(json_obj_mk_obj, "key", &key_obj)) {
        json_object_object_get_ex(keys_obj, json_object_get_string(key_obj), &key_category_obj);
        json_object_object_get_ex(key_category_obj, "material", &material_obj);
        json_object_object_get_ex(key_category_obj, "encoding", &encoding_obj);

        if (!json_object_object_get_ex(key_category_obj, "key-id", &key_id_obj)) {
            fprintf(stderr, "Failed to obtain key-id\n");
            goto next_test_scenario;
        }

        key_name = aws_string_new_from_c_str(alloc, json_object_get_string(key_id_obj));
    }

    json_object_object_get_ex(json_obj_mk_obj, "provider-id", &provider_id_obj);
    if (provider_id_obj) key_namespace = aws_string_new_from_c_str(alloc, json_object_get_string(provider_id_obj));

    json_object_object_get_ex(json_obj_mk_obj, "encryption-algorithm", &encryption_algorithm_obj);

    if (!cmp_jsonstr_with_cstr(key_type_obj, "raw")) {
        if (!key_namespace) {
            fprintf(stderr, "Failed to obtain key_namespace\n");
            goto next_test_scenario;
        }

        if (!key_name) {
            fprintf(stderr, "Failed to obtain key_name \n");
            goto next_test_scenario;
        }

        if (!cmp_jsonstr_with_cstr(encryption_algorithm_obj, "aes")) {
            test_type_idx = AWS_CRYPTOSDK_AES;
            if (!material_obj) {
                fprintf(stderr, "Failed to obtain the raw aes key material, %s\n", aws_error_str(aws_last_error()));
                goto next_test_scenario;
            }

            if (cmp_jsonstr_with_cstr(encoding_obj, "base64")) {
                fprintf(stderr, "Failed to obtain base64 string\n");
                goto next_test_scenario;
            }

            struct aws_byte_buf decoded_material;
            if (get_base64_decoded_material(alloc, &decoded_material, material_obj)) {
                fprintf(stderr, "Failed to obtain the base64 decoded material \n");
                goto next_test_scenario;
            }

            if (!(kr = aws_cryptosdk_raw_aes_keyring_new(
                      alloc,
                      key_namespace,
                      key_name,
                      decoded_material.buffer,
                      (enum aws_cryptosdk_aes_key_len)decoded_material.len))) {
                fprintf(
                    stderr,
                    "Failed to initialize aws_cryptosdk_raw_aes_keyring, %s\n",
                    aws_error_str(aws_last_error()));
                goto next_test_scenario;
            }
        } else if (!cmp_jsonstr_with_cstr(encryption_algorithm_obj, "rsa")) {
            test_type_idx = AWS_CRYPTOSDK_RSA;
            if (!material_obj) {
                fprintf(stderr, "Failed to obtain the raw rsa key material, %s\n", aws_error_str(aws_last_error()));
                goto next_test_scenario;
            }
            const char *pem_file = json_object_get_string(material_obj);
            if (cmp_jsonstr_with_cstr(encoding_obj, "pem")) {
                fprintf(stderr, "Failed to obtain rsa pem string\n");
                goto next_test_scenario;
            }
            json_object *padding_algorithm_obj = NULL, *padding_hash_obj = NULL;

            json_object_object_get_ex(json_obj_mk_obj, "padding-algorithm", &padding_algorithm_obj);
            const char *padding_algorithm = json_object_get_string(padding_algorithm_obj);
            if (!padding_algorithm) {
                fprintf(stderr, "Failed to obtain padding algorithm \n");
                goto next_test_scenario;
            }

            json_object_object_get_ex(json_obj_mk_obj, "padding-hash", &padding_hash_obj);
            const char *padding_hash = json_object_get_string(padding_hash_obj);

            enum aws_cryptosdk_rsa_padding_mode padding_mode;
            if (!get_padding_mode(&padding_mode, padding_algorithm, padding_hash)) {
                not_supported = true;
                goto next_test_scenario;
            }
            if (!(kr = aws_cryptosdk_raw_rsa_keyring_new(
                      alloc, key_namespace, key_name, pem_file, NULL, padding_mode))) {
                fprintf(
                    stderr,
                    "Failed to initialize aws_cryptosdk_raw_rsa_keyring, %s\n",
                    aws_error_str(aws_last_error()));
                goto next_test_scenario;
            }
        }
    } else if (!cmp_jsonstr_with_cstr(key_type_obj, "aws-kms")) {
        test_type_idx = AWS_CRYPTOSDK_KMS;
        if (!key_id_obj) {
            fprintf(stderr, "Failed to obtain the kms_key_id, %s\n", aws_error_str(aws_last_error()));
            goto next_test_scenario;
        }
        const Aws::String key_id = json_object_get_string(key_id_obj);
        kr                       = KmsKeyring::Builder().WithClientSupplier(client_supplier).Build({ key_id });
        if (!kr) {
            fprintf(stderr, "Failed to initialize aws_cryptosdk_kms_keyring, %s\n", aws_error_str(aws_last_error()));
            goto next_test_scenario;
        }
    } else if (!cmp_jsonstr_with_cstr(key_type_obj, "aws-kms-mrk-aware")) {
        test_type_idx = AWS_CRYPTOSDK_KMS_MRK_AWARE;
        if (!key_id_obj) {
            fprintf(stderr, "Failed to obtain the kms_key_id, %s\n", aws_error_str(aws_last_error()));
            goto next_test_scenario;
        }
        const Aws::String key_id = json_object_get_string(key_id_obj);
        kr = KmsMrkAwareSymmetricKeyring::Builder().WithClientSupplier(client_supplier).Build({ key_id });
        if (!kr) {
            fprintf(stderr, "Failed to initialize aws_cryptosdk_kms_keyring, %s\n", aws_error_str(aws_last_error()));
            goto next_test_scenario;
        }
    } else if (!cmp_jsonstr_with_cstr(key_type_obj, "aws-kms-mrk-aware-discovery")) {
        test_type_idx = AWS_CRYPTOSDK_KMS_MRK_AWARE_DISCOVERY;

        json_object *default_mrk_region_obj = NULL;
        json_object_object_get_ex(json_obj_mk_obj, "default-mrk-region", &default_mrk_region_obj);
        if (!default_mrk_region_obj) {
            fprintf(stderr, "Failed to obtain the default MRK region \n");
            goto next_test_scenario;
        }
        const Aws::String default_mrk_region = json_object_get_string(default_mrk_region_obj);
        Aws::Client::ClientConfiguration client_config;
        client_config.region = default_mrk_region;

        std::function<void()> report_success;
        auto kms_client = client_supplier->GetClient(default_mrk_region, report_success);
        report_success();

        json_object *discovery_filter_obj = NULL;
        json_object_object_get_ex(json_obj_mk_obj, "aws-kms-discovery-filter", &discovery_filter_obj);
        if (discovery_filter_obj) {
            shared_ptr<KmsKeyring::DiscoveryFilter> discovery_filter = get_discovery_filter(discovery_filter_obj);
            if (discovery_filter == nullptr) {
                fprintf(stderr, "Failed to obtain the discovery filter \n");
                goto next_test_scenario;
            }
            kr = KmsMrkAwareSymmetricKeyring::Builder()
                     .WithKmsClient(kms_client)
                     .BuildDiscovery(default_mrk_region, discovery_filter);
        } else {
            kr = KmsMrkAwareSymmetricKeyring::Builder().WithKmsClient(kms_client).BuildDiscovery(default_mrk_region);
        }

        if (!kr) {
            fprintf(stderr, "Failed to initialize aws_cryptosdk_kms_keyring, %s\n", aws_error_str(aws_last_error()));
            goto next_test_scenario;
        }
    } else {
        const char *key_type = json_object_get_string(key_type_obj);
        fprintf(stderr, "Unknown key type, %s\n", key_type);
        goto next_test_scenario;
    }

next_test_scenario:
    if (key_namespace) aws_string_destroy(key_namespace);
    if (key_name) aws_string_destroy(key_name);

    return kr;
}

static int run_test_decryption(
    struct aws_cryptosdk_session *session,
    std::string ct_filename,
    uint8_t *ciphertext,
    size_t ct_len,
    uint8_t *plaintext,
    size_t pt_len,
    struct expected_outcome expected) {
    uint8_t *output_buffer = (uint8_t *)malloc(pt_len);
    if (!output_buffer) abort();
    size_t out_produced = 0;
    if (!expected.success) {
        // If the test case is expected to fail, populate the output buffer
        // so we can assert it is zeroed out.
        memset(output_buffer, 0xFF, pt_len);
    }

    int result = AWS_OP_SUCCESS;

    int process_result =
        aws_cryptosdk_session_process_full(session, output_buffer, pt_len, &out_produced, ciphertext, ct_len);
    if (!expected.success) {
        if (process_result == AWS_OP_SUCCESS) {
            fprintf(
                stderr,
                "Unexpected success while processing aws_crytosdk_session. Expected error description: %s\n",
                expected.error_desc.c_str());
            result = AWS_OP_ERR;
            goto cleanup;
        }
        if (!aws_is_mem_zeroed(output_buffer, pt_len)) {
            fprintf(
                stderr, "Output not zeroed after expected decryption failure for test case %s\n", ct_filename.c_str());
            result = AWS_OP_ERR;
            goto cleanup;
        }
    } else {
        if (process_result != AWS_OP_SUCCESS) {
            fprintf(stderr, "Error while processing aws_crytosdk_session, %s\n", aws_error_str(aws_last_error()));
            result = AWS_OP_ERR;
            goto cleanup;
        }

        if (!aws_cryptosdk_session_is_done(session)) {
            fprintf(
                stderr,
                "Error while processing aws_crytosdk_session, decryption not complete, %s\n",
                aws_error_str(aws_last_error()));
            result = AWS_OP_ERR;
            goto cleanup;
        }

        if (pt_len != out_produced) {
            fprintf(
                stderr,
                "Wrong output size, PlainText length = %zu, Produced output length = %zu\n",
                pt_len,
                out_produced);
            result = AWS_OP_ERR;
            goto cleanup;
        }

        if (memcmp(output_buffer, plaintext, pt_len)) {
            fprintf(stderr, "Plaintext mismatch for test case %s\n", ct_filename.c_str());
            result = AWS_OP_ERR;
            goto cleanup;
        }
    }

cleanup:
    if (output_buffer) free(output_buffer);

    return result;
}

static void kms_delay(test_type test_type_idx) {
    static int fifty_millis = 50000;
    usleep(fifty_millis);
    /*
    if ((test_type_idx == AWS_CRYPTOSDK_KMS) || (test_type_idx == AWS_CRYPTOSDK_KMS_MRK_AWARE) ||
        (test_type_idx == AWS_CRYPTOSDK_KMS_MRK_AWARE_DISCOVERY)) {
        usleep(fifty_millis);
    }
    */
}

static int process_test_scenarios(
    struct aws_allocator *alloc,
    struct expected_outcome expected,
    std::string ct_filename,
    enum aws_cryptosdk_mode mode,
    json_object *master_keys_obj,
    json_object *keys_obj,
    const shared_ptr<KmsKeyring::ClientSupplier> &client_supplier) {
    struct aws_cryptosdk_keyring *multi_keyring = NULL;

    struct aws_cryptosdk_session *session = NULL;
    struct aws_cryptosdk_cmm *cmm         = NULL;
    uint8_t *ciphertext                   = NULL;
    uint8_t *plaintext                    = NULL;
    size_t ct_len                         = 0;
    size_t pt_len                         = 0;

    enum test_type test_type_idx;
    for (int j = 0; j < json_object_array_length(master_keys_obj); j++) {
        json_object *json_obj_mk_obj = json_object_array_get_idx(master_keys_obj, j);

        bool not_supported;
        struct aws_cryptosdk_keyring *kr = keyring_for_master_key_spec(
            alloc, json_obj_mk_obj, keys_obj, test_type_idx, not_supported, client_supplier);
        kms_delay(test_type_idx);
        if (!kr) {
            if (expected.success) {
                if (not_supported) {
                    not_yet_supported++;
                } else {
                    failed++;
                }
            } else {
                passed++;
            }
            goto next_test_scenario;
        }

        if (j == 0) {
            multi_keyring = aws_cryptosdk_multi_keyring_new(alloc, kr);
            if (!multi_keyring) {
                failed++;
                fprintf(stderr, "Failed to initialize multi_keyring, %s\n", aws_error_str(aws_last_error()));
                aws_cryptosdk_keyring_release(kr);
                goto next_test_scenario;
            }
        } else {
            if (AWS_OP_SUCCESS != aws_cryptosdk_multi_keyring_add_child(multi_keyring, kr)) {
                failed++;
                fprintf(stderr, "Failed to add keyring to multi_keyring, %s\n", aws_error_str(aws_last_error()));
                aws_cryptosdk_keyring_release(kr);
                goto next_test_scenario;
            }
        }

        aws_cryptosdk_keyring_release(kr);
    }

    if (!(cmm = aws_cryptosdk_default_cmm_new(alloc, multi_keyring))) {
        failed++;
        fprintf(stderr, "Failed to initialize aws_cryptosdk_default_cmm, %s\n", aws_error_str(aws_last_error()));
        goto next_test_scenario;
    }

    if (!(session = aws_cryptosdk_session_new_from_cmm_2(alloc, mode, cmm))) {
        failed++;
        fprintf(stderr, "Failed to initialize aws_cryptosdk_session, %s\n", aws_error_str(aws_last_error()));
        goto next_test_scenario;
    }
    aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT);

    if (test_loadfile(ct_filename.c_str(), &ciphertext, &ct_len)) {
        failed++;
        fprintf(
            stderr, "Failed to load ciphertext file %s, %s\n", ct_filename.c_str(), aws_error_str(aws_last_error()));
        goto next_test_scenario;
    }

    if (expected.success && test_loadfile(expected.pt_filename.c_str(), &plaintext, &pt_len)) {
        failed++;
        fprintf(
            stderr,
            "Failed to load plaintext file %s, %s\n",
            expected.pt_filename.c_str(),
            aws_error_str(aws_last_error()));
        goto next_test_scenario;
    }

    if (run_test_decryption(session, ct_filename, ciphertext, ct_len, plaintext, pt_len, expected)) {
        failed++;
        goto next_test_scenario;
    }

    test_type_passed[test_type_idx]++;
    passed++;

next_test_scenario:
    if (ciphertext) free(ciphertext);
    if (plaintext) free(plaintext);
    if (session) aws_cryptosdk_session_destroy(session);
    if (cmm) aws_cryptosdk_cmm_release(cmm);
    if (multi_keyring) aws_cryptosdk_keyring_release(multi_keyring);

    return AWS_OP_SUCCESS;
}

static int test_vector_runner(const char *path, const char *test_name) {
    char manifest_filename[256];
    char *key;

    struct json_object *val;
    struct lh_entry *entry;
    struct aws_allocator *alloc = aws_default_allocator();
    struct expected_outcome expected;

    json_object *manifest_obj          = NULL;
    json_object *tests_obj             = NULL;
    json_object *keys_obj              = NULL;
    json_object *test_case_obj         = NULL;
    json_object *result_obj            = NULL;
    json_object *result_output_obj     = NULL;
    json_object *result_error_obj      = NULL;
    json_object *pt_filename_obj       = NULL;
    json_object *err_desc_obj          = NULL;
    json_object *ct_filename_obj       = NULL;
    json_object *master_keys_obj       = NULL;
    json_object *keys_manifest_obj     = NULL;
    json_object *decryption_method_obj = NULL;

    std::shared_ptr<Aws::Cryptosdk::KmsKeyring::ClientSupplier> client_supplier =
        Aws::Cryptosdk::Testing::CredentialCachingClientSupplier::Create();

    if (snprintf(manifest_filename, sizeof(manifest_filename), "%s/manifest.json", path) >= sizeof(manifest_filename)) {
        fprintf(stderr, "Path too long\n");
        return AWS_OP_ERR;
    }
    json_object *manifest_jso_obj = json_object_from_file(manifest_filename);

    TEST_ASSERT(json_object_object_get_ex(manifest_jso_obj, "manifest", &manifest_obj));
    TEST_ASSERT_SUCCESS(verify_manifest_type_and_version(manifest_obj));
    TEST_ASSERT(json_object_object_get_ex(manifest_jso_obj, "tests", &tests_obj));

    std::string find_str = "file:/";

    TEST_ASSERT(json_object_object_get_ex(manifest_jso_obj, "keys", &keys_obj));

    std::string keys_filename = json_object_get_string(keys_obj);
    keys_filename.replace(keys_filename.find(find_str), find_str.length(), path);

    json_object *keys_manifest_jso_obj = json_object_from_file(keys_filename.c_str());
    TEST_ASSERT(json_object_object_get_ex(keys_manifest_jso_obj, "keys", &keys_obj));
    TEST_ASSERT(json_object_object_get_ex(keys_manifest_jso_obj, "manifest", &keys_manifest_obj));

    TEST_ASSERT_SUCCESS(verify_keys_manifest_type_and_version(keys_manifest_obj));

    for (entry = json_object_get_object(tests_obj)->head;
         (entry ? (key = (char *)entry->k, val = (struct json_object *)entry->v, entry) : 0);
         entry = entry->next) {
        if (test_name != NULL && strcmp(test_name, key)) {
            continue;
        }

        TEST_ASSERT(json_object_object_get_ex(tests_obj, key, &test_case_obj));
        TEST_ASSERT(json_object_object_get_ex(val, "ciphertext", &ct_filename_obj));
        TEST_ASSERT(json_object_object_get_ex(val, "result", &result_obj));
        if (json_object_object_get_ex(result_obj, "output", &result_output_obj)) {
            expected.success = true;
            TEST_ASSERT(json_object_object_get_ex(result_output_obj, "plaintext", &pt_filename_obj));
            std::string pt_filename = json_object_get_string(pt_filename_obj);
            pt_filename.replace(pt_filename.find(find_str), find_str.length(), path);
            expected.pt_filename = pt_filename;
        } else if (json_object_object_get_ex(result_obj, "error", &result_error_obj)) {
            expected.success = false;
            TEST_ASSERT(json_object_object_get_ex(result_error_obj, "error-description", &err_desc_obj));
            expected.error_desc = json_object_get_string(err_desc_obj);
        } else {
            fprintf(stderr, "Unrecognized result type\n");
            return AWS_OP_ERR;
        }

        std::string ct_filename = json_object_get_string(ct_filename_obj);
        ct_filename.replace(ct_filename.find(find_str), find_str.length(), path);

        enum aws_cryptosdk_mode mode = AWS_CRYPTOSDK_DECRYPT;
        if (json_object_object_get_ex(val, "decryption-method", &decryption_method_obj)) {
            std::string decryption_method = json_object_get_string(decryption_method_obj);
            if (decryption_method == "streaming-unsigned-only") {
                mode = AWS_CRYPTOSDK_DECRYPT_UNSIGNED;
            }
        }

        TEST_ASSERT(json_object_object_get_ex(val, "master-keys", &master_keys_obj));
        int failed_before = failed;
        TEST_ASSERT_SUCCESS(
            process_test_scenarios(alloc, expected, ct_filename, mode, master_keys_obj, keys_obj, client_supplier));
        if (failed_before < failed) {
            fprintf(stderr, "Failures in test %s\n", key);
        }
    }
    printf("Decryption successfully completed for %d test cases and failed for %d.\n", passed, failed);
    printf(
        "AES Passed = %d, RSA Passed = %d, KMS Passed = %d, Encrypt-only = %d, Not-yet-supported = %d.\n",
        test_type_passed[0],
        test_type_passed[1],
        test_type_passed[2],
        encrypt_only,
        not_yet_supported);
    return failed ? AWS_OP_ERR : AWS_OP_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(
            stderr,
            "Wrong number of arguments\nUsage: ./static_test_vectors /path/to/manifest/files [test-UUID-to-run]\n");
        return EXIT_FAILURE;
    }
    aws_cryptosdk_load_error_strings();
    SDKOptions options;

    Aws::InitAPI(options);
    // Initialize logging to show when KMS calls are made
    Aws::Utils::Logging::InitializeAWSLogging(Aws::MakeShared<Aws::Utils::Logging::ConsoleLogSystem>(
        "static_test_vectors.cpp", Aws::Utils::Logging::LogLevel::Debug));

    const char *test_name = NULL;
    if (argc == 3) {
        test_name = argv[2];
    }
    int rv = test_vector_runner(argv[1], test_name);
    Aws::ShutdownAPI(options);
    return rv;
}
