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

#include <aws/core/utils/Outcome.h>
#include <aws/core/Aws.h>
#include <aws/kms/model/EncryptRequest.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/kms/model/DecryptRequest.h>
#include <aws/kms/model/DecryptResult.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
#include <aws/kms/model/GenerateDataKeyResult.h>

#include "kms_shim_mock.h"
#include "testutil.h"
#include "kms_client_mock.h"
#include "testing.h"

using namespace Aws::Cryptosdk::Testing;
using namespace Aws::Cryptosdk::Private;

using Aws::SDKOptions;

const char *CLASS_TAG = "KMS_SHIM_CTAG";

struct TestData {
    const char *key_id = "data_key_id";
    const char *pt = "Plaintext";
    const char *ct = "Ciphertext";
    Aws::Utils::ByteBuffer pt_bb;
    Aws::Utils::ByteBuffer ct_bb;
    std::shared_ptr<KmsClientMock> kms_client;
    KmsShim kms_shim;
    Aws::Map<Aws::String, Aws::String> empty_enc_context;

    TestData() : pt_bb((u_char *) pt, strlen(pt)),
                 ct_bb((u_char *) ct, strlen(ct)),
                 kms_client(std::make_shared<KmsClientMock>()),
                 kms_shim(kms_client, key_id) {
    }
};

struct EncryptData : public TestData {
    Model::EncryptRequest request;
    Model::EncryptResult result;

    EncryptData() {
        request.SetKeyId(key_id);
        request.SetPlaintext(pt_bb);

        result.SetCiphertextBlob(ct_bb);
    }
};

struct DecryptData : public TestData {
    Model::DecryptRequest request;
    Model::DecryptResult result;

    DecryptData() {
        request.SetCiphertextBlob(ct_bb);

        result.SetPlaintext(pt_bb);
    }
};

struct GenerateDataKeyData : public TestData {
    Model::GenerateDataKeyRequest request;
    Model::GenerateDataKeyResult result;
    int number_of_bytes = 12;

    GenerateDataKeyData() {
        request.SetKeyId(key_id);
        request.SetNumberOfBytes(number_of_bytes);

        result.SetPlaintext(pt_bb);
        result.SetCiphertextBlob(ct_bb);
    }
};

int encrypt_validInputes_returnSuccess() {
    EncryptData ed;

    Model::EncryptOutcome outcome_in(ed.result);
    ed.kms_client->ExpectEncrypt(ed.request, outcome_in);

    Model::EncryptOutcome outcome_out = ed.kms_shim.Encrypt(ed.pt_bb, ed.empty_enc_context);

    TEST_ASSERT(outcome_out.IsSuccess() == true);
    TEST_ASSERT(outcome_out.GetResult().GetCiphertextBlob() == outcome_in.GetResult().GetCiphertextBlob());
    TEST_ASSERT(outcome_out.GetResult().GetKeyId() == outcome_in.GetResult().GetKeyId());

    return 0;
}

int decrypt_validInputes_returnSuccess() {
    DecryptData dd;

    Model::DecryptOutcome outcome_in(dd.result);
    dd.kms_client->ExpectDecrypt(dd.request, outcome_in);

    Model::DecryptOutcome outcome_out = dd.kms_shim.Decrypt(dd.ct_bb, dd.empty_enc_context);

    TEST_ASSERT(outcome_out.IsSuccess() == true);
    TEST_ASSERT(outcome_out.GetResult().GetPlaintext() == outcome_in.GetResult().GetPlaintext());
    TEST_ASSERT(outcome_out.GetResult().GetKeyId() == outcome_in.GetResult().GetKeyId());

    return 0;
}

int generate_dk_validInputes_returnSuccess() {
    GenerateDataKeyData gd;

    Model::GenerateDataKeyOutcome outcome_in(gd.result);
    gd.kms_client->ExpectGenerateDataKey(gd.request, outcome_in);

    Model::GenerateDataKeyOutcome outcome_out = gd.kms_shim.GenerateDataKey(gd.number_of_bytes, gd.empty_enc_context);

    TEST_ASSERT(outcome_out.IsSuccess() == true);
    TEST_ASSERT(outcome_out.GetResult().GetPlaintext() == outcome_in.GetResult().GetPlaintext());
    TEST_ASSERT(outcome_out.GetResult().GetCiphertextBlob() == outcome_in.GetResult().GetCiphertextBlob());
    TEST_ASSERT(outcome_out.GetResult().GetKeyId() == outcome_in.GetResult().GetKeyId());

    return 0;
}

//TODO add tests for encryption context and for grant_tokensgrant_tokens

int main() {
    SDKOptions *options = Aws::New<SDKOptions>(CLASS_TAG);
    Aws::InitAPI(*options);

    RUN_TEST(encrypt_validInputes_returnSuccess());
    RUN_TEST(decrypt_validInputes_returnSuccess());
    RUN_TEST(generate_dk_validInputes_returnSuccess());

    Aws::ShutdownAPI(*options);
    Aws::Delete(options);
}
