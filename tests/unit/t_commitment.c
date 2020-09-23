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

#include <aws/common/common.h>
#include <aws/common/encoding.h>
#include <aws/cryptosdk/default_cmm.h>
#include <aws/cryptosdk/private/cipher.h>
#include <aws/cryptosdk/session.h>
#include <stdlib.h>
#include "counting_keyring.h"
#include "testing.h"
#include "testutil.h"
#include "zero_keyring.h"

struct stub_keyring {
    struct aws_cryptosdk_keyring base;
    struct aws_allocator *alloc;

    struct aws_byte_buf data_key;
};

static void stub_keyring_destroy(struct aws_cryptosdk_keyring *kr) {
    struct stub_keyring *stub = (struct stub_keyring *)kr;

    aws_byte_buf_clean_up(&stub->data_key);
    aws_mem_release(stub->alloc, stub);
}

AWS_STATIC_STRING_FROM_LITERAL(static_stub_str, "stub");

static int stub_keyring_decrypt(
    struct aws_cryptosdk_keyring *kr,
    struct aws_allocator *request_alloc,
    struct aws_byte_buf *unencrypted_data_key,
    struct aws_array_list *keyring_trace,
    const struct aws_array_list *edks,
    const struct aws_hash_table *enc_ctx,
    enum aws_cryptosdk_alg_id alg) {
    struct stub_keyring *stub = (struct stub_keyring *)kr;

    struct aws_byte_cursor c = aws_byte_cursor_from_buf(&stub->data_key);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy(unencrypted_data_key, request_alloc, &stub->data_key)) {
        return AWS_OP_ERR;
    }

    aws_cryptosdk_keyring_trace_add_record(
        request_alloc, keyring_trace, static_stub_str, static_stub_str, AWS_CRYPTOSDK_WRAPPING_KEY_DECRYPTED_DATA_KEY);

    return AWS_OP_SUCCESS;
}

const static struct aws_cryptosdk_keyring_vt stub_keyring_vt = { .vt_size    = sizeof(stub_keyring_vt),
                                                                 .name       = "stub keyring",
                                                                 .destroy    = stub_keyring_destroy,
                                                                 .on_decrypt = stub_keyring_decrypt,
                                                                 .on_encrypt = NULL };

static struct aws_cryptosdk_keyring *stub_keyring_new(struct aws_allocator *alloc, const char *data_key_b64) {
    struct stub_keyring *kr = aws_mem_acquire(alloc, sizeof(*kr));
    if (!kr) {
        return NULL;
    }

    kr->alloc    = alloc;
    kr->data_key = easy_b64_decode(data_key_b64);

    aws_cryptosdk_keyring_base_init(&kr->base, &stub_keyring_vt);

    return &kr->base;
}

struct commitment_kat_case {
    const char *ciphertext_b64;
    const char *datakey_b64;
    const char *comment;
    bool should_succeed;
};

static const struct commitment_kat_case TEST_CASES[] = {
    { .ciphertext_b64 = "AgR4TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXkAAA"
                        "ABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAz45sc3cDvJ"
                        "Z7D4P3sAMKE7d/w8ziQt2C0qHsy1Qu2E2q92eIGE/kLnF/Y003"
                        "HKvTxx7xv2Zv83YuOdwHML5QIAABAAF88I9zPbUQSfOlzLXv+u"
                        "IY2+m/E6j2PMsbgeHVH/L0wLqQlY+5CL0z3xnNOMIZae/////w"
                        "AAAAEAAAAAAAAAAAAAAAEAAAAOSZBKHHRpTwXOFTQVGapXXj5C"
                        "wXBMouBB2ucaIJVm",
      .datakey_b64    = "+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0=",
      .comment        = "1. Non-KMS key provider",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4b1/73X5ErILpj0aSQIx6wNnHLEcNLxPzA0m6vYRr7kAAAA"
                        "ABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAypJmXwyizU"
                        "r3/pyvIAMHLU/i5GhZlGayeYC5w/CjUobyGwN4QpeMB0XpNDGT"
                        "M0f1Zx72V4uM2H5wMjy/hm2wIAABAAAAECAwQFBgcICQoLDA0O"
                        "DxAREhMUFRYXGBkaGxwdHh/pQM2VSvliz2Qgi5JZf2ta/////w"
                        "AAAAEAAAAAAAAAAAAAAAEAAAANS4Id4+dVHhPrvuJHEiOswo6Y"
                        "GSRjSGX3VDrt+0s=",
      .datakey_b64    = "8Bu+AFAu9ZT8BwYK+QAKXKQ2iaySSiQwlPUrKMf6fdo=",
      .comment        = "2. Non-KMS key provider (Expected Failure)",
      .should_succeed = false },
    { .ciphertext_b64 = "AgV4vjf7DnZHP0MgQ4/QHZH1Z/1Lt24oyMR0DigenSpro9wAjg"
                        "AEAAUwVGhpcwACaXMAAzFhbgAKZW5jcnlwdGlvbgAIMmNvbnRl"
                        "eHQAB2V4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQX"
                        "RnM3JwOEVBNFFhNnBmaTk3MUlTNTk3NHpOMnlZWE5vSmtwRHFP"
                        "c0dIYkVaVDRqME5OMlFkRStmbTFVY01WdThnPT0AAQAHYXdzLW"
                        "ttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgz"
                        "MzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYm"
                        "IyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIug"
                        "vbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSI"
                        "b3DQEHATAeBglghkgBZQMEAS4wEQQMOTLXUpQGBjgD+EYIAgEQ"
                        "gDsqRrwjQTGW0pA78dc+2Y/IqUrG7eAO4hZ07BNJEnd1d3+gUq"
                        "W6Yunk8qyN9ryxdY8s4PshzJ7lyXIDuwIAABAABc0DWynVSZ1F"
                        "h1cLh1Aq/mNPeyzD3yqpiKEBBUosdod2yzOfJTZ0H1mhwgJPJZ"
                        "Sr/////wAAAAEAAAAAAAAAAAAAAAEAAAAJ+m45xgKSc5k+9oOl"
                        "ZEBdaNvusGVs1XyesABnMGUCMCoWR62YhnklwXEuj63nCz8qK8"
                        "O4UOuR71bP3RiWfZHYQtkrrzV7ukj2Nseghpyt4gIxAKquEtCP"
                        "igr+heUFSAMRDJ7YEbLgisSgUqkHQhfqOwG2YFNKySG/CR0SNl"
                        "fisJNovQ==",
      .datakey_b64    = "FX5R4LJUJ1XkzcV5GGRS9MSdtc+2kzyvEsVFiETwdi4=",
      .comment        = "3. Non-KMS key provider (with ECDSA)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        "ACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw9EJqts2Pk"
                        "PA43eeMCARCAO9JPXvk6hofpX8P50mlDfAEwIiJc9sTS82KeLP"
                        "BiZRnvmWcf2YSceNCoKTOB819M1auXncAYO8JJ/VzPAAdhd3Mt"
                        "a21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwOD"
                        "MzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVh"
                        "NWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgW"
                        "av8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZI"
                        "hvcNAQcBMB4GCWCGSAFlAwQBLjARBAw4v1P6lkHuuyIOZ7ECAR"
                        "CAO0iAkJa/Ivo37+t5rryGAGMiIHuamdq21HBOULwcGmMzCT69"
                        "PWNgm1l59xq+8AOinEEzohfm2jBueXA2AgAAEABDPYN/Wct+m8"
                        "YzTRVK/4MRCcY3LZj4tayFiL/376umUUTUenheMypVEflUomVb"
                        "lvr/////AAAAAQAAAAAAAAAAAAAAAQAAAAlCp+rAMHiuKyGr0K"
                        "RmjDC6C7TXAvAwtFjR",
      .datakey_b64    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      .comment        = "4. Key = zero, Message ID = zero",
      .should_succeed = true },
    { .ciphertext_b64 = "AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3"
                        "aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWm"
                        "lPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEC"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDOl5m0bj8TSUWO4GBwIBEIA7V0a+DvNMcb"
                        "D7jfMcMuk0Rz8vB3oEp9wlIATpXzJmjqWefsFPJy5izbrFcR5C"
                        "ydFN2KS3h7E/9AjlQiUAB2F3cy1rbXMAS2Fybjphd3M6a21zOn"
                        "VzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRk"
                        "ZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPc"
                        "MYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZI"
                        "hvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBA"
                        "EuMBEEDIbOPUE8vBwp3Z6CLQIBEIA7mvK9rkzLwhrM+A8KXqqf"
                        "j6pktEbnUrfggiAYnpss2KuZhM/vh/ha1SE9mSXwd4SFGVYOG5"
                        "Q9/WevH1ICAAAQAEM9g39Zy36bxjNNFUr/gxEJxjctmPi1rIWI"
                        "v/fvq6ZRrGZZkIZ1T4L6ZU5vqj/DrP////8AAAABAAAAAAAAAA"
                        "AAAAABAAAACYppWXO1LeMi/qxGk3haWIs2N4VSEWHPa7cAZzBl"
                        "AjAnb0SKcZVySyKIYvYvJA0yDUuftkXNoi01Umw+9MpwGh/y3c"
                        "R3+TKU4DnNuljEkfACMQCNMCiS30oMIWNlhrWBQ852fhfhLvg8"
                        "jLGIYLwFhEE9NrnyDYfj2H8Ej7+qK4C9OTY=",
      .datakey_b64    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      .comment        = "5. Key = zero, Message ID = zero (signed)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAA"
                        "ACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyLV34wpxvM"
                        "YsbEiU8CARCAO0bxzvbstOlsWM526OaxxrXGZcngJ/76lY0BzO"
                        "XIX9AXwtTsJo665uBaTIr4/vRykIKYzaZHSAuXKsdgAAdhd3Mt"
                        "a21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwOD"
                        "MzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVh"
                        "NWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgW"
                        "av8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZI"
                        "hvcNAQcBMB4GCWCGSAFlAwQBLjARBAzI7Ml/HzSTtW5N/8wCAR"
                        "CAO8cdJ+NTV5FmL2ct3yQSJDgoyBdZPBdm4jU9l4jcDt5lbYFd"
                        "1zDxgPeNk31VXLPNsX0mTx0OaEPIK6KlAgAAEAACl+KPtzMY6h"
                        "HYeXFawsClEaCgrwZP3NxMctmWVgd4gnqay0u/SsaSuLWWsLJs"
                        "7bH/////AAAAAf//////////AAAAAQAAAAlL5waUrU/1SiTVGf"
                        "tdt6I+oiP381iEHj9x",
      .datakey_b64    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      .comment        = "6. Key = zero, Message ID = example",
      .should_succeed = true },
    { .ciphertext_b64 = "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3"
                        "aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWm"
                        "lPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEC"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDLIcLILCEW0b/akcFQIBEIA7sN7bHvnMwO"
                        "Lqzk8ZQgRTZSyIRSbXV8XucXF6jh/cB6q7KQHak72WGEowX06j"
                        "+q1CmqIHQsHgLJJ7Y7cAB2F3cy1rbXMAS2Fybjphd3M6a21zOn"
                        "VzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRk"
                        "ZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPc"
                        "MYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZI"
                        "hvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBA"
                        "EuMBEEDEJci+3Rbh2YQr2wVgIBEIA78+/l+kW07ZozOJ/aA2eZ"
                        "3KlNAy6rT6DC/18vT+rT8kXgJAtvcLfYGL8QvVcZnxeLX4ebtz"
                        "dzIWmUZhACAAAQAAKX4o+3MxjqEdh5cVrCwKURoKCvBk/c3Exy"
                        "2ZZWB3iCOgF1daFLUF+WmSaKQstsl/////8AAAAB//////////"
                        "8AAAABAAAACQY49UBR9fGrbSLGqwWF/gAL17cwTR18A5MAZjBk"
                        "AjAKrkLQ1xAPssfM1rfJibkZQb0260Mm2vRCetEgl3RDJx/sBS"
                        "xnRBZo53aRQHML6rwCMHmqQaG/tBzeWp9N0xengvRNL7eHJFSL"
                        "xbCCgOOHlUllPWa03oYrvRCUPQ9RfREeDg==",
      .datakey_b64    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      .comment        = "7. Key = zero, Message ID = example (signed)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        "ACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzyYxT13KXw"
                        "mUdiy88CARCAOzGOUQoGACVGrO4G0peHG71kP2zcDJpbdgZwUJ"
                        "BED49U3gpnQpBTWp2hp1N7Qti/fxNTccVKGZzutdZoAAdhd3Mt"
                        "a21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwOD"
                        "MzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVh"
                        "NWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgW"
                        "av8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZI"
                        "hvcNAQcBMB4GCWCGSAFlAwQBLjARBAwP+Chc1R00x7BpDcsCAR"
                        "CAO3vvz3yc9wbc2BBLvX0Mdc4Z5gVDOCLOXuNiSNmCFqHAZqVg"
                        "wQZPJb8xg+LQ0Li+luAffrro75j4bV3ZAgAAEABCgKFhvD9vTC"
                        "e32kD42QLPj7aksASoP1T02N4az5lpkszyG+f3sYswBonWP9Rw"
                        "XEv/////AAAAAf//////////AAAAAQAAAAl9Q+pOIP6ElqvCiP"
                        "y7rOA36dQnyyOGg463",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "8. Key = example, Message ID = zero",
      .should_succeed = true },
    { .ciphertext_b64 = "AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3"
                        "aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWm"
                        "lPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEC"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDHeEI3Z1nYS1NsWO3gIBEIA7kheJ0Nc6B3"
                        "mnlQSehdOnpAQfk1DWf4Yio61pzLJJxdjAL/mxnkczLPTUbbbQ"
                        "KPwyAozKoE324+Tbu0wAB2F3cy1rbXMAS2Fybjphd3M6a21zOn"
                        "VzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRk"
                        "ZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPc"
                        "MYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZI"
                        "hvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBA"
                        "EuMBEEDGY7wZesL6TorCErTwIBEIA7/+0ch6ZtFmPqI8Ukrwue"
                        "qwRBJsFGNWcFqgL9jnyVGkw9Nb422X9wzAvmAZxffxbdmTNEzT"
                        "aQPiOTpOMCAAAQAEKAoWG8P29MJ7faQPjZAs+PtqSwBKg/VPTY"
                        "3hrPmWmSO8OkA7vPXdTYugnXxz8umP////8AAAAB//////////"
                        "8AAAABAAAACcv5HJwalZMTSUDIh9Z5MNr+qA7gnMqHxM0AZzBl"
                        "AjEAin8CuSVzytkAqI+TiqPyaslB8bb1OFd2RY1xUuIeFCmYZS"
                        "o+53ok5nyTquzxEGRLAjALrF/ggOtvZ8qUNJCWaYOz9UGYll3Y"
                        "mU8de0x6NEwCj5XednEd8Jesw9mOZ5+qbSg=",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "9. Key = example, Message ID = zero (signed)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAA"
                        "ACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAx3EP1N/Lum"
                        "YE8aNewCARCAO8m7yeBMjLVEHoeMmbylI3QdPRoqp+mJDgcN5y"
                        "keh5OpAr7flh9VlZcik9OOPViXcGSKodlDLibhi1W1AAdhd3Mt"
                        "a21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwOD"
                        "MzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVh"
                        "NWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgW"
                        "av8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZI"
                        "hvcNAQcBMB4GCWCGSAFlAwQBLjARBAztBB+UBueMi1l2QyQCAR"
                        "CAOw8NELkDmYdYArDjxBiHF3nlbbMjhPN/6tsCTrryk78nIe1k"
                        "Uj6dhOW4jv9UAK9v8II+kLeOwq1JsCr0AgAAEADxsVyYp96/hp"
                        "K+FPm+py4GHisVMco6nM7oDHr08PByitCSr8UpuX4JwQvWDz3E"
                        "m/b/////AAAAAf//////////AAAAAQAAAAnIeIJlIPwbFrcG23"
                        "2KWGshMJ9+1gKublnM",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "10. Key = example, Message ID = example",
      .should_succeed = true },
    { .ciphertext_b64 = "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3"
                        "aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWm"
                        "lPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEC"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDFJv9+79usIu0JHDLwIBEIA7SELzODxUMV"
                        "bIbIzq4Bxlq5VgO5IByEOFWGi+Q+NxyubE2cwXwVLptW6y/jiL"
                        "n6CGrDaBzxuthwHgxmEAB2F3cy1rbXMAS2Fybjphd3M6a21zOn"
                        "VzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRk"
                        "ZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPc"
                        "MYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZI"
                        "hvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBA"
                        "EuMBEEDFGVND+QpXSW67k+5gIBEIA7Lm792H0cZeQGH0D1MXjY"
                        "nkOdjSMRSCSjU9nmMwEuOdr16kYAXBul9dY4KpWyRNTfrWJxfo"
                        "EZh4uldlcCAAAQAPGxXJin3r+Gkr4U+b6nLgYeKxUxyjqczugM"
                        "evTw8HKKxiu8Qpy4U65J+9ZSXS4lv/////8AAAAB//////////"
                        "8AAAABAAAACYT3EZfkxPxdFqk/tnQn8jJN2OYvIcbqw7cAaDBm"
                        "AjEAhszsRN2RAPaEgspAJwZYi0LcrM+8glcTL3HwNlzUHEkd75"
                        "YGVKb/UNAElxXU6IKCAjEAmiw4LPFwAJ6ex2VwIIo++injUUHa"
                        "1BfiF2HMpqnB5jruGCk3KxS64h0NvdPco6nW",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "11. Key = example, Message ID = example (signed)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAA"
                        "ACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzWRW49EX50"
                        "QiQO8gsCARCAO5sgMFpr76NxknbZ8CCeup3xNPeF2Mm7Fm0l17"
                        "+Le0DdI8MBujB9lyGmQWMWIXq5URWbHKLN7sqiM2yiAAdhd3Mt"
                        "a21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwOD"
                        "MzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVh"
                        "NWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgW"
                        "av8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZI"
                        "hvcNAQcBMB4GCWCGSAFlAwQBLjARBAyXAus4K5pnm0NpcJ8CAR"
                        "CAO0HKCnxolKBLsbqRPh/WaXxQi1VkJoz/oOVfL4+IFQymTsgK"
                        "MGgHtFG77hngnoSJQyFPo6b/sMuN4KVKAgAAEAC0UBWiNYSJJv"
                        "XRl/IXIBh0uo/DOGcPO1rP+V/sOGmM+bZERA+G8H4wcefWYWZ8"
                        "dv7/////AAAAAf//////////AAAAAQAAAAkgsJoIIYNmoGTtuN"
                        "rrNcRdC3nxmJaY+Bhu",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "12. Two different plaintext data keys, same ciphertext",
      .should_succeed = false },
    { .ciphertext_b64 = "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3"
                        "aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWm"
                        "lPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEC"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDBJwQx7rLsF9SMURIgIBEIA76C0ub3htb4"
                        "Bo0ZgIAoYSRzahiRunNMjvEfZ4oAUq0v6q7BQeeZXFuH0Dycxu"
                        "IwJuaftxZDUR6GEPfA8AB2F3cy1rbXMAS2Fybjphd3M6a21zOn"
                        "VzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRk"
                        "ZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPc"
                        "MYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZI"
                        "hvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBA"
                        "EuMBEEDFCRxguNQerLwoT9TQIBEIA7a9HTYxjgD8GssZNegRz3"
                        "dwDmNp4NGohmVxI3wwwL1ZxJzSIkwsuwKobQbbNWH149c0fhZy"
                        "HJX5dk3OoCAAAQALRQFaI1hIkm9dGX8hcgGHS6j8M4Zw87Ws/5"
                        "X+w4aYz5UtBXqCzIpb8Cd4/WZwbHh/////8AAAAB//////////"
                        "8AAAABAAAACYedXbtB+YnSiC8XC2WPDytoXd+hEH9zWv8AaDBm"
                        "AjEAuhsI42YXIDtHJV9QNXWxh1QefwdH8yjcz1ewdCJKHrLFpm"
                        "vCy5vErQduqGRXSotVAjEAvQNjxDDpDGRjictnjev+3slPy927"
                        "Jr0SXs7xa/AslIsZHJNI/WQrPc7KVq6DzKKT",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "13. Two different plaintext data keys, same ciphertext (signed)",
      .should_succeed = false },
    { .ciphertext_b64 = "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOg"
                        "ACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOm"
                        "F3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1"
                        "MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQ"
                        "IAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAA"
                        "fjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBg"
                        "lghkgBZQMEAS4wEQQMVS2kQTl1wrYLE2eLAgEQgDulTL6UW+E6"
                        "FTj+tivbEgzVQCko4XyfLCHO9p6+XhhzZ4ASQdB+InX3zlUO0n"
                        "zvo6ncpznnFwucVziULgAHYXdzLWttcwBLYXJuOmF3czprbXM6"
                        "dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZG"
                        "RkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9"
                        "wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8Bgkqhk"
                        "iG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQME"
                        "AS4wEQQM3CmTGX0yeaiG9NrQAgEQgDsnrSa/wp3e/eyjabdqfN"
                        "OdRCgPRfrJg+bSSzs6Y8WogxrrXuCdv/Gxd/tpoGgrfckTXXAv"
                        "Dyzh2snYXAIAABAAApfij7czGOoR2HlxWsLApRGgoK8GT9zcTH"
                        "LZllYHeIL5z/RijnIgTxn9phSilA70/////wAAAAH/////////"
                        "/wAAAAEAAAAJS+cGlK1P9Uok1Rn7XbeiPqIj9/NYhB4/cQ==",
      .datakey_b64    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      .comment        = "14. Key = zero, Message ID = example (with AAD)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlw"
                        "ADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibG"
                        "ljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlR"
                        "VHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT"
                        "0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1"
                        "ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNW"
                        "EtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlk"
                        "raPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAg"
                        "EAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMlgzxMfOV"
                        "ccgo/NfWAgEQgDuBa8xMNPel0q7fr4r9y9cKoeaaxqo5vLVr/K"
                        "NnDbzr13J3Edl70FJhu9iuS3E9Ed81jwt8FeIntzPfuQAHYXdz"
                        "LWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMD"
                        "gzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1"
                        "YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMI"
                        "Fmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqG"
                        "SIb3DQEHATAeBglghkgBZQMEAS4wEQQMiz3Umk1/gWN+lSq5Ag"
                        "EQgDvGK8/b7k6VRkOHOwisVDZilScjgbNNHNWnPJjo7NKm2/8t"
                        "///KTjL/QJ/zD5cLsEInvsyltBX9jEd83gIAABAAApfij7czGO"
                        "oR2HlxWsLApRGgoK8GT9zcTHLZllYHeIIg5X2rC+bMh/YSXh8A"
                        "crNA/////wAAAAH//////////wAAAAEAAAAJBjj1QFH18attIs"
                        "arBYX+AAvXtzBNHXwDkwBnMGUCMQC3jREI99riv0SYM2G3dYMv"
                        "A26KOHM/f7lhd6VQdM0MX+fHo/LfTEanr2AW9UlustkCMCpX/x"
                        "8S84qJeTQbnTS0OCEvSjRCWluK4xqnSTc2PvZiOTALHUVBTkvR"
                        "xBRnaUPa/g==",
      .datakey_b64    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      .comment        = "15. Key = zero, Message ID = example (signed, with AAD)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOg"
                        "ACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOm"
                        "F3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1"
                        "MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQ"
                        "IAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAA"
                        "fjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBg"
                        "lghkgBZQMEAS4wEQQMFEBnKyt3QstLVqt+AgEQgDvjFgXze5zC"
                        "18mw1EL22Sk1L9s2x/d/yyKUFVcqcxsIN0YBh9nOUkMji/Kbar"
                        "oJticmBBH5iVuC58W7CAAHYXdzLWttcwBLYXJuOmF3czprbXM6"
                        "dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZG"
                        "RkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9"
                        "wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8Bgkqhk"
                        "iG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQME"
                        "AS4wEQQMpstDQzF757dbNzujAgEQgDtMFvMf2MmJumFtDnpVae"
                        "1UIZqEhrFGIgtRDd/BVPeA3KZA+HzImTd0bNiOnL6flxyITvnj"
                        "MkXAstQa3wIAABAAQoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9N"
                        "jeGs+ZaZJzgj4W/ZtkD2K6nrgp64FH/////wAAAAH/////////"
                        "/wAAAAEAAAAJfUPqTiD+hJarwoj8u6zgN+nUJ8sjhoOOtw==",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "16. Key = example, Message ID = zero (with AAD)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlw"
                        "ADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibG"
                        "ljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlR"
                        "VHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT"
                        "0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1"
                        "ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNW"
                        "EtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlk"
                        "raPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAg"
                        "EAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM5vYU7k2t"
                        "K4Y4ChgDAgEQgDu7X3F084Gf5T+8/cP+Qge/+xj8lZN95hogWx"
                        "YwC/HA649wqOHc2dvQeP0rc7OJIUj8QwmCcITyAWvRXgAHYXdz"
                        "LWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMD"
                        "gzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1"
                        "YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMI"
                        "Fmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqG"
                        "SIb3DQEHATAeBglghkgBZQMEAS4wEQQMbxIh5bCSDVpF64zaAg"
                        "EQgDsKuqZd6LSW4WtYmeQcydeqQbxnYXzhDlSla6QNcknXuOaA"
                        "CDsonsrh6+0tk7Z1OOA0Jxbrcx8oojE0WgIAABAAQoChYbw/b0"
                        "wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZKuxbySIS3cRk6BGotn"
                        "okRl/////wAAAAH//////////wAAAAEAAAAJy/kcnBqVkxNJQM"
                        "iH1nkw2v6oDuCcyofEzQBnMGUCMQCmRHBH53c9klyofyrrze8i"
                        "/Al0AW4K2/3lJF1lc7yV43y2FI1jOByqzsEvu4NjYTgCMDUiSC"
                        "mLWNOZUdLhGzA7+6q3al2b0eDfV/zpsIKZrQPZccRftNTbxR/m"
                        "1Wo7udndPg==",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "17. Key = example, Message ID = zero (signed, with AAD)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOg"
                        "ACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOm"
                        "F3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1"
                        "MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQ"
                        "IAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAA"
                        "fjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBg"
                        "lghkgBZQMEAS4wEQQMA0otLRQxvR8Ud+pKAgEQgDvVR2YZbiRG"
                        "nzk9VHphC2z0gf/3fnC856VJsjDHyXfeveuOAOg8lHBR2yqcbV"
                        "6kFafqsLGuhoNM7kVkhAAHYXdzLWttcwBLYXJuOmF3czprbXM6"
                        "dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZG"
                        "RkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9"
                        "wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8Bgkqhk"
                        "iG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQME"
                        "AS4wEQQM+7tKI00Bt/e3ZvEiAgEQgDtVAzyv+65kZInUtQjH5u"
                        "EkHKcMGXPDWMGjaGo5u8AEVGkwM+Sph6+lykd21OT67IqUt6g2"
                        "5v8O0+PBSwIAABAA8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6A"
                        "x69PDwcopiz5Sh5k0vkhhnD960r/31/////wAAAAH/////////"
                        "/wAAAAEAAAAJyHiCZSD8Gxa3Btt9ilhrITCfftYCrm5ZzA==",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "18. Key = example, Message ID = example (with AAD)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlw"
                        "ADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibG"
                        "ljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlR"
                        "VHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT"
                        "0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1"
                        "ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNW"
                        "EtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlk"
                        "raPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAg"
                        "EAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMxOjP1UAe"
                        "C+vE5J1fAgEQgDvgHwPc3KpNStTjhawDEa7Z5UDCnKwSH5KaTY"
                        "T0Qbnu2o3RVgjLQxsa5FjdBUzi3lusy2g4HRMeGgk5QQAHYXdz"
                        "LWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMD"
                        "gzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1"
                        "YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMI"
                        "Fmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqG"
                        "SIb3DQEHATAeBglghkgBZQMEAS4wEQQMKTHgS3LLlQH3xP7EAg"
                        "EQgDu+iRlWxVymazFlhKAAaNkQhpZzxyljqYBgctCjsmVwSfic"
                        "4+VH5gOLsLyNUC0JwqNHTH5+hcphGVgXTQIAABAA8bFcmKfev4"
                        "aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcormGII0al4n1z8nUbSV"
                        "XezJ/////wAAAAH//////////wAAAAEAAAAJhPcRl+TE/F0WqT"
                        "+2dCfyMk3Y5i8hxurDtwBoMGYCMQCES2bdqjxadCcKb/NgzQ+K"
                        "xCXix0VBh0mJwKyyUXvwjUFoGJkecdswSXhPiYO7EocCMQDWPw"
                        "hemHv5ObNVjv9iEmTF5wghBIi3aYeY4N3QQRcPtkuCdcaqKRR3"
                        "u8VzZsFR9eg=",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "19. Key = example, Message ID = example (signed, with AAD)",
      .should_succeed = true },
    { .ciphertext_b64 = "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOg"
                        "ACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOm"
                        "F3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1"
                        "MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQ"
                        "IAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAA"
                        "fjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBg"
                        "lghkgBZQMEAS4wEQQMa0HbVm3pJUfxLRYYAgEQgDuR/OmD0OFs"
                        "gzBNOppbGC20b+e4iMYVRb2/MocrN8fFc+/lC6ERZzLFh90CO4"
                        "QEcKKfelssXufLxx7qLAAHYXdzLWttcwBLYXJuOmF3czprbXM6"
                        "dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZG"
                        "RkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9"
                        "wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8Bgkqhk"
                        "iG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQME"
                        "AS4wEQQM4PTMwlCPPqF2SFfOAgEQgDtHXTkMqX6j3VPqV9RxZj"
                        "lPEGGB3twqK2eX8g2kAKYIObPvJNZvsDHR0ge8k0U9eQ7WDBwC"
                        "wyaNsDpCiwIAABAAtFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/"
                        "lf7DhpjPlwqyAp6svYC2BmtqRuFAlr/////wAAAAH/////////"
                        "/wAAAAEAAAAJILCaCCGDZqBk7bja6zXEXQt58ZiWmPgYbg==",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "20. Two different plaintext data keys, same ciphertext (with AAD)",
      .should_succeed = false },
    { .ciphertext_b64 = "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlw"
                        "ADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibG"
                        "ljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlR"
                        "VHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT"
                        "0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1"
                        "ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNW"
                        "EtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlk"
                        "raPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAg"
                        "EAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMrp6QFLdm"
                        "NOISqjdzAgEQgDuCXiJsMNKTfNWmYDoMnJcI+oRQBeIl0d1pZB"
                        "u5pBxGgS6chIfLVbcmweuUZDk0TCJLah7PVv3JfTSpLQAHYXdz"
                        "LWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMD"
                        "gzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1"
                        "YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMI"
                        "Fmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqG"
                        "SIb3DQEHATAeBglghkgBZQMEAS4wEQQM1QFgfyGcwGCV+dGjAg"
                        "EQgDvI+3I0/U4wng4yWrV4RYtozOmW+lgipeTBRm3+6icDcD0A"
                        "/8gzF6t4LjzgNm812nbcazbYazNAvd0xuwIAABAAtFAVojWEiS"
                        "b10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPlwgv4XNIzljFNfv4FZ"
                        "ni21/////wAAAAH//////////wAAAAEAAAAJh51du0H5idKILx"
                        "cLZY8PK2hd36EQf3Na/wBnMGUCMQCRoSvXwlzNpXaMoH3xaSwR"
                        "Kxekj1t8GpfiULRl/KEjC6gRIWYcxV2zmMy1DCqwC7sCMHVZkw"
                        "/zs6sbyWcMPz1Rsl6kM2lSm8BWls9ZIqw7yF3I4fob1sdjxu0i"
                        "IRwYrtSlSg==",
      .datakey_b64    = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
      .comment        = "21. Two different plaintext data keys, same ciphertext (signed, with AAD)",
      .should_succeed = false },

    { 0 }
};

static int test_one(const struct commitment_kat_case *t) {
    struct aws_byte_buf ciphertext   = easy_b64_decode(t->ciphertext_b64);
    struct aws_cryptosdk_keyring *kr = stub_keyring_new(aws_default_allocator(), t->datakey_b64);
    TEST_ASSERT_ADDR_NOT_NULL(kr);

    struct aws_cryptosdk_cmm *cmm = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);
    TEST_ASSERT_ADDR_NOT_NULL(cmm);

    struct aws_byte_buf plaintext;
    TEST_ASSERT_SUCCESS(aws_byte_buf_init(&plaintext, aws_default_allocator(), ciphertext.len));

    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_cmm(aws_default_allocator(), AWS_CRYPTOSDK_DECRYPT, cmm);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_keyring_release(kr);

    size_t consumed, produced;
    int rv = aws_cryptosdk_session_process(
        session, plaintext.buffer, plaintext.capacity, &produced, ciphertext.buffer, ciphertext.len, &consumed);

    if (t->should_succeed) {
        TEST_ASSERT_SUCCESS(rv);
        TEST_ASSERT(aws_cryptosdk_session_is_done(session));
    } else {
        TEST_ASSERT_INT_NE(AWS_OP_SUCCESS, rv);
    }

    aws_cryptosdk_session_destroy(session);
    aws_byte_buf_clean_up(&plaintext);
    aws_byte_buf_clean_up(&ciphertext);

    return 0;
}

static int test_known_answers() {
    int failed = 0;
    for (int i = 0; TEST_CASES[i].ciphertext_b64; i++) {
        if (TEST_CASES[i].datakey_b64[0] == '\0') {
            fprintf(stderr, "[ SKIP ] %s\n", TEST_CASES[i].comment);
            continue;
        }

        int rv = test_one(&TEST_CASES[i]);
        if (rv) {
            fprintf(stderr, "[FAILED] %s\n", TEST_CASES[i].comment);
            failed = 1;
        } else {
            fprintf(stderr, "[  OK  ] %s\n", TEST_CASES[i].comment);
        }
    }

    return failed;
}

static int valid_policy() {
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);

    TEST_ASSERT_SUCCESS(
        aws_cryptosdk_session_set_commitment_policy(session, COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT));

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

static int invalid_policy() {
    struct aws_cryptosdk_keyring *kr = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    struct aws_cryptosdk_session *session =
        aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);

    TEST_ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_cryptosdk_session_set_commitment_policy(session, 0x42424242));

    /* Session should be broken */
    uint8_t ct_buf[1024], pt_buf[1] = { 0 };
    size_t pt_consumed, ct_produced;

    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_process(
            session, ct_buf, sizeof(ct_buf), &ct_produced, pt_buf, sizeof(pt_buf), &pt_consumed));

    aws_cryptosdk_session_destroy(session);
    aws_cryptosdk_keyring_release(kr);

    return 0;
}

/**
 * This test only applies to v1.7, since in v2.0 the commitment policy is set by default.
 */
static int test_session_fail_without_commitment_policy() {
    struct aws_cryptosdk_keyring *kr;
    struct aws_cryptosdk_cmm *cmm;
    struct aws_cryptosdk_session *session;

    uint8_t ct_buf[1024], pt_buf[16];
    size_t ct_len, pt_advanced, ct_consumed;

    kr      = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    session = aws_cryptosdk_session_new_from_keyring_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, kr);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, 0));
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_process(session, ct_buf, sizeof(ct_buf), &ct_len, "", 0, &pt_advanced));
    aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_process(session, pt_buf, sizeof(pt_buf), &pt_advanced, ct_buf, ct_len, &ct_consumed));
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_session_destroy(session);

    kr      = aws_cryptosdk_zero_keyring_new(aws_default_allocator());
    cmm     = aws_cryptosdk_default_cmm_new(aws_default_allocator(), kr);
    session = aws_cryptosdk_session_new_from_cmm_2(aws_default_allocator(), AWS_CRYPTOSDK_ENCRYPT, cmm);
    TEST_ASSERT_SUCCESS(aws_cryptosdk_session_set_message_size(session, 0));
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_process(session, ct_buf, sizeof(ct_buf), &ct_len, "", 0, &pt_advanced));
    aws_cryptosdk_session_reset(session, AWS_CRYPTOSDK_DECRYPT);
    TEST_ASSERT_ERROR(
        AWS_CRYPTOSDK_ERR_BAD_STATE,
        aws_cryptosdk_session_process(session, pt_buf, sizeof(pt_buf), &pt_advanced, ct_buf, ct_len, &ct_consumed));
    aws_cryptosdk_keyring_release(kr);
    aws_cryptosdk_cmm_release(cmm);
    aws_cryptosdk_session_destroy(session);

    return 0;
}

struct test_case commitment_test_cases[] = {
    { "commitment", "known_answer", test_known_answers },
    { "commitment", "valid_policy", valid_policy },
    { "commitment", "invalid_policy", invalid_policy },
    { "commitment", "fail_without_policy", test_session_fail_without_commitment_policy },
    { NULL }
};
