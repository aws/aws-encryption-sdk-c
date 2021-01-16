    {
        .ciphertext_b64 =
                        "AgR4TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXkAAA"
                        "ABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAz45sc3cDvJ"
                        "Z7D4P3sAMKE7d/w8ziQt2C0qHsy1Qu2E2q92eIGE/kLnF/Y003"
                        "HKvTxx7xv2Zv83YuOdwHML5QIAABAAF88I9zPbUQSfOlzLXv+u"
                        "IY2+m/E6j2PMsbgeHVH/L0wLqQlY+5CL0z3xnNOMIZae/////w"
                        "AAAAEAAAAAAAAAAAAAAAEAAAAOSZBKHHRpTwXOFTQVGapXXj5C"
                        "wXBMouBB2ucaIJVm",
        .datakey_b64 = "+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0=",
        .comment = "1. Non-KMS key provider",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4b1/73X5ErILpj0aSQIx6wNnHLEcNLxPzA0m6vYRr7kAAAA"
                        "ABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAypJmXwyizU"
                        "r3/pyvIAMHLU/i5GhZlGayeYC5w/CjUobyGwN4QpeMB0XpNDGT"
                        "M0f1Zx72V4uM2H5wMjy/hm2wIAABAAAAECAwQFBgcICQoLDA0O"
                        "DxAREhMUFRYXGBkaGxwdHh/pQM2VSvliz2Qgi5JZf2ta/////w"
                        "AAAAEAAAAAAAAAAAAAAAEAAAANS4Id4+dVHhPrvuJHEiOswo6Y"
                        "GSRjSGX3VDrt+0s=",
        .datakey_b64 = "8Bu+AFAu9ZT8BwYK+QAKXKQ2iaySSiQwlPUrKMf6fdo=",
        .comment = "2. Non-KMS key provider (Expected Failure)",
        .should_succeed = false
    },
    {
        .ciphertext_b64 =
                        "AgV4vjf7DnZHP0MgQ4/QHZH1Z/1Lt24oyMR0DigenSpro9wAjg"
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
        .datakey_b64 = "FX5R4LJUJ1XkzcV5GGRS9MSdtc+2kzyvEsVFiETwdi4=",
        .comment = "3. KMS key provider (with ECDSA)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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
        .datakey_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .comment = "4. Key = zero, Message ID = zero",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXw"
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
        .datakey_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .comment = "5. Key = zero, Message ID = zero (signed)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAA"
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
        .datakey_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .comment = "6. Key = zero, Message ID = example",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXw"
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
        .datakey_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .comment = "7. Key = zero, Message ID = example (signed)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "8. Key = example, Message ID = zero",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXw"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "9. Key = example, Message ID = zero (signed)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAA"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "10. Key = example, Message ID = example",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXw"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "11. Key = example, Message ID = example (signed)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAA"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "12. Two different plaintext data keys, same ciphertext",
        .should_succeed = false
    },
    {
        .ciphertext_b64 =
                        "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXw"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "13. Two different plaintext data keys, same ciphertext (signed)",
        .should_succeed = false
    },
    {
        .ciphertext_b64 =
                        "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOg"
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
        .datakey_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .comment = "14. Key = zero, Message ID = example (with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlw"
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
        .datakey_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .comment = "15. Key = zero, Message ID = example (signed, with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOg"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "16. Key = example, Message ID = zero (with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlw"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "17. Key = example, Message ID = zero (signed, with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOg"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "18. Key = example, Message ID = example (with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlw"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "19. Key = example, Message ID = example (signed, with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOg"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "20. Two different plaintext data keys, same ciphertext (with AAD)",
        .should_succeed = false
    },
    {
        .ciphertext_b64 =
                        "AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlw"
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
        .datakey_b64 = "Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=",
        .comment = "21. Two different plaintext data keys, same ciphertext (signed, with AAD)",
        .should_succeed = false
    },
    {
        .ciphertext_b64 =
                        "AgR4ZzjLWV5kAQKVlXj57IcJa1iEqTYVzYLoqG8PRUdtGnEAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzm/W4IEwyw"
                        "1XGMDx8CARCAOzWxBU81iv0uAE17I6C3HxgVlMZm2br9GAktcy"
                        "J5IgZKA6N8MLzLAmbDoMb1HxJEKkb8F49QTArCUhX7AgAAEADr"
                        "eoUk9jDTH/FR/nDtTKFjBD6r2ipZhT5LsJtgx2rbJGBYOeO5FC"
                        "ZSGlsZTIsoNDL/////AAAAAQAAAAAAAAAAAAAAAQAAAAm5gmDN"
                        "/oEFl97JI39GIyXlS3CudSGOWm8p",
        .datakey_b64 = "4aY8MK4AdgTXDgz7DXIUfOZ81MR7/v8Vh1qS4hha4U4=",
        .comment = "22. Simple JS encrypt",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4BiIWGA4lhe6nW3EBq9ri5hyuIcvnhaWt6s6yP70JnwQAOg"
                        "ACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOm"
                        "F3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1"
                        "MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQ"
                        "EAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAA"
                        "fjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBg"
                        "lghkgBZQMEAS4wEQQM4qQYbJbU6HvDqgEBAgEQgDsSqi/xWCa5"
                        "VP0Ax1s+G6AIZ3GkNE2kR2WzLYXpA9HCZ4pny25nD5vguvGtbd"
                        "KGR4TlpTPkxvUTa+LHNQIAABAAbzal1s5Ht+XmPGs+lzwMTU3V"
                        "sVKI1h73jcUgz4G30oAmkkGJNdjmZFflISSBirPH/////wAAAA"
                        "EAAAAAAAAAAAAAAAEAAAAJ5LRWdzEYzFurmIpJRc9PzENBizW3"
                        "+v7/Qg==",
        .datakey_b64 = "/tCswbBkCYGs0DgkPDm775OnlQXO6N8zWLMTuHvPrqg=",
        .comment = "23. Simple JS encrypt (with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4iCL3obBFAgl2H4KE8R96eNgBjLqFzwofaagV/SF1UJgAOg"
                        "ACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAU"
                        "YW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOm"
                        "F3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1"
                        "MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQ"
                        "EAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAA"
                        "fjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBg"
                        "lghkgBZQMEAS4wEQQMFUkHCQBWWWqXIwgfAgEQgDt+DtsGGoRX"
                        "X/c2o6u8WUX7EPdRCBuYBjKTEexmgld+jqfu9ogp+XVs/lEPCn"
                        "ThJE7lZ26ufBNtuZpNZwIAAAABW3KhrYH9MFe3n+Js+v5arMzH"
                        "mH58k/3TjhBfn28QENxyh41IeBjszPCSS9P1WjiFAAAAAQAAAA"
                        "AAAAAAAAAAATFhtmleghwYLnacJo9PvJ8zAAAAAgAAAAAAAAAA"
                        "AAAAAqN1bVJRZ7u4SxGPLFCAaUCIAAAAAwAAAAAAAAAAAAAAAx"
                        "HeThX1MRHvZDw6RRc0GbaMAAAABAAAAAAAAAAAAAAABLxdlMXx"
                        "vjmARlkmTHYjH0MaAAAABQAAAAAAAAAAAAAABYpcAmbgJbPAei"
                        "4O+8e/7rC8AAAABgAAAAAAAAAAAAAABnylrtV/x7G9ll5XX7+l"
                        "5qPkAAAABwAAAAAAAAAAAAAAB92sSPXn8rtFFw/H8zMcax38AA"
                        "AACAAAAAAAAAAAAAAACOg8ggvUao5tOL/CqpTEdNHpAAAACQAA"
                        "AAAAAAAAAAAACSaxo/DM3P6NKU3BPlZAubgR/////wAAAAoAAA"
                        "AAAAAAAAAAAAoAAAAAhh5ydHx1RXNFYRN5zY0jhg==",
        .datakey_b64 = "0fdi6NBvUeXX+pmFX6SUir0Q7/q5b2cQJJOtJpbWC5Q=",
        .comment = "24. JS encrypt (with AAD) 1byte frame",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4nod6k6U3+hHpc2+9TE2fJvNJYmXxy5HKeGP2976E24wAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFydDRid3dTWVFU"
                        "dnJpRUJQcWpDVzhWMTdMYkNidHNtb0F4MHpXdTFxa2Nnd0lVUW"
                        "VOV2RnckJnVWhQTEkxUE9ZQT09AAEAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEB"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDJpAGhSRmDYszjWV6wIBEIA7uVaaElPbdk"
                        "hU606jGGVzlu7jtdib9n7IEBMxhTveoM3I7Jx4WeEp5V6PJJVR"
                        "lYgSaYnWZgd+pyNo7uUCAAAQAEhoaOayTlJx1SbHzfKvoTojWN"
                        "zxHF2S8tryntZVRRBV13bvyHPyFxkLMXVkCze8V/////8AAAAB"
                        "AAAAAAAAAAAAAAABAAAACTCts6F2Ov1/AGioyQndGwQnZw3UZl"
                        "O38WoAZjBkAi9JY1EB/YcIGvwbkjfvlzraylN1beJzTZuIKzMW"
                        "vQAMUPaLe80Szxw/F8p9KPlhKgIxAP/+fRUljLTg5Inw7LeAyW"
                        "8oFBQNuSgmdIAZavogUFU+e1A+kQtvWdHUiLA0DgElQg==",
        .datakey_b64 = "rnlg7ipPE0mbNg7SiAf039ey9BjswFQyHOPiLp5u1V4=",
        .comment = "25. Simple JS encrypt (signed)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4SRXxd2NDKOwAK7EYmcVdoN70/a4cd0UQxPLBy8QlCBcAlw"
                        "ADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF2VE4rUkR2UzJI"
                        "SG1URk1KZCtGNFNMMGl0MXdvVTZOL0tSU2FQVng2WWREdkQrZV"
                        "lvSmZiT0JNcnh3MnNqM3ZkQT09AAh0ZXN0LWtleQAKdGVzdCB2"
                        "YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbG"
                        "UAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1"
                        "ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNW"
                        "EtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlk"
                        "raPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAg"
                        "EAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMLtjZcR8p"
                        "arum7ZR3AgEQgDv09dkEH/ruNg2NegEnyE70usveM7797/b0Iu"
                        "EMu+0SDqES0zViAvGONZJsV67nHYbNPrs8lsPb9AwCCAIAABAA"
                        "kbBHwH7I84SFz+s/eagR9kB1Oo1VEJLCWf+8p9CEdvS7eYYjth"
                        "sdoDEufe8ssndV/////wAAAAEAAAAAAAAAAAAAAAEAAAAJSV1n"
                        "7Qqi45oXfU2nLU8ZNKAsGlCjF62apQBoMGYCMQC7CzoB18g7LB"
                        "HxmbaC/TscsTkeSIoztKh9LzWrdny6AX5KXedpKkj957mlLFJ7"
                        "xvkCMQC/BpMw8W6hnEa8yQyJNRtKvg8i9UhbV2tJ7kGzpE0nUN"
                        "csUn/1BwR1AHYv0MtLIy4=",
        .datakey_b64 = "RtABha+g0NdkwR43yxTAIFHmVm3dN2UuYywpNUarrF0=",
        .comment = "26. Simple JS encrypt (signed with AAD)",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV41wCZ4BqY2Cx0CxGm8/koQpqTRMu8nP1ntIHLGLxB9X4Alw"
                        "ADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFuaEdPcGM4TVM1"
                        "NFdWTjJteTB3NHhaOVk1M1h5RTRIeFpBSUJPTlRrYW9UT3NOU0"
                        "xJVEJVRXVVVmNnVjJOK0ZsZz09AAh0ZXN0LWtleQAKdGVzdCB2"
                        "YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbG"
                        "UAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1"
                        "ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNW"
                        "EtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlk"
                        "raPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAg"
                        "EAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMpMUYWP28"
                        "5UGw/AmCAgEQgDtmuzcaMPiY+zoGW/HupbJJOTicJEzFGYqz8V"
                        "D/uYbapQixhJMYJAfVDU6N7f/tsMBckKE1JAAm4/NpfAIAAAAB"
                        "GDzmHkvsXZw/S51Z2IwF5tXFhiM47NTo+UiRotqRuOAKAW9WKd"
                        "5x2ONAuWrzDDcUAAAAAQAAAAAAAAAAAAAAAYtOnuOM43FbAh8Y"
                        "QX42NmIyAAAAAgAAAAAAAAAAAAAAAm2fsrBCSB0FgjPZYIzgMT"
                        "UdAAAAAwAAAAAAAAAAAAAAA1bydLuJbuThvFatZ5Lzm4AzAAAA"
                        "BAAAAAAAAAAAAAAABDokA1/+j4d+3wCNTYy6iIVjAAAABQAAAA"
                        "AAAAAAAAAABYc0mcYJjilk8+MwijGHFtE6AAAABgAAAAAAAAAA"
                        "AAAABqvmulDqkXcIBKNGBM/awn4+AAAABwAAAAAAAAAAAAAAB8"
                        "TbxRI0xBDBBUkGOc1l4e53AAAACAAAAAAAAAAAAAAACNPZlcny"
                        "tPsFK2iqj/JV9LU7AAAACQAAAAAAAAAAAAAACeLMC3KMhVfzTA"
                        "GG4q9Yclp3/////wAAAAoAAAAAAAAAAAAAAAoAAAAAIyJHRhgr"
                        "+RXwWwmgULn3dwBmMGQCMBAuknmnfN782mJM/SB/fXc1x1uwyU"
                        "sdvjlfSFDP0LX4YfwcXvehapxu/06ciltuHwIwJkbmdd+qrKTu"
                        "pj6UE6JR/ia19qPx3BF8XccN5AyDeKZ5nk/+4q/KfW5+D8inMu"
                        "V0",
        .datakey_b64 = "YW6c551XES/jyr5MtVN1vkCG2+wxgxePpDGyk2K871M=",
        .comment = "27. JS encrypt (signed with AAD) 1byte frame",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4fhEwYp4uvtSjKKVBRNo8M4cCzGNZCYJlKZ6dNV2TBPEAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyjF8TPWFNe"
                        "TAVPNiUCARCAOwHa2IwF6OfmFdnZ1thO3nryExnRRrpV6SuDQM"
                        "cVE4kN7GJSLMjUNKOHWy+tc6w4GJ8YZQPaXh3FZpi5AQAAAACB"
                        "QTGyBZRrmYgb72ew18KF56PZxUWaw0tTi22YAY/r6oGdS+5h09"
                        "VRBcpMLGuaDu4AAAAAAAAAAAAAAAEAAAAAAAAAQJIOz+8G3/o/"
                        "pAvlKSNdtiPli7T/33N3BIOT8XsWqnzSF5JEYpaNdFpKLC6t9z"
                        "gK6HHBr73ehnL1yHPU3FvWBqeD8QDElTDQ3prt4rUiN8kN",
        .datakey_b64 = "5SD48CW8Md8mKuygllS+zJlE5X8mhIqk+5nq3e2lnhU=",
        .comment = "28. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; unframed",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4r4RshhYvCOY/ajQPeb54T49paP2DVvo2PfIXU+3hbTUAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyEE40xvDMt"
                        "H0/MW9YCARCAO40maS/hEokvZST+ZLwNSRl4kFobypfiG9Prki"
                        "vJeUZfuKYL3biHGamGxbcO0GhiuVNIUpLTnOjqD8g/AgAAAAH8"
                        "Bm55usOgGEMbDyTfJicgxdHefqLxo+HuXSKndykWA8gq5RRBe5"
                        "igAl5sT7DzowYAAAABAAAAAAAAAAAAAAABMA4WqB8EkMeJx4cy"
                        "Q70WV5oAAAACAAAAAAAAAAAAAAACQmmAo07TB+dSz16QkT1OS8"
                        "EAAAADAAAAAAAAAAAAAAADQzZ/MMfXCFpUnLygsyjBnDQAAAAE"
                        "AAAAAAAAAAAAAAAEwQ+A9y7/neEzHvOPT0JZJgEAAAAFAAAAAA"
                        "AAAAAAAAAFBcu7alEz/i5L0uvZxpzzq5UAAAAGAAAAAAAAAAAA"
                        "AAAGrwGWbfW/8RnfzLkAXra0W1kAAAAHAAAAAAAAAAAAAAAHBc"
                        "DtQxYl1mOlndLEQfEYjFwAAAAIAAAAAAAAAAAAAAAIBPx3Qwbk"
                        "m09/lz2nvmjn2OkAAAAJAAAAAAAAAAAAAAAJamWvUMnS/CAp9L"
                        "4KL1wAhsIAAAAKAAAAAAAAAAAAAAAKyqKVWZigTf58AxE7A+xL"
                        "mREAAAALAAAAAAAAAAAAAAALwLY1R7bouUXkAd1YoI7HBmwAAA"
                        "AMAAAAAAAAAAAAAAAMY/RCtOfKSkeBh4xJf16ZCQQAAAANAAAA"
                        "AAAAAAAAAAAN8WoUr0cqxQ89aDrSddvk+W8AAAAOAAAAAAAAAA"
                        "AAAAAOHYYJKq1QV3/6V1WcuD5Y/R0AAAAPAAAAAAAAAAAAAAAP"
                        "/m5+y5/NXjZZnkVjPrvSA9gAAAAQAAAAAAAAAAAAAAAQbXsEM/"
                        "qCXhBWrPa4BgHTS8kAAAARAAAAAAAAAAAAAAARKOgYlYSnm+u4"
                        "sn2XcmGnQ5wAAAASAAAAAAAAAAAAAAASMwkW7YxzIfyAvhO5/y"
                        "kV0JoAAAATAAAAAAAAAAAAAAATkhOKrtMO+BxeuDWm4sXsmE8A"
                        "AAAUAAAAAAAAAAAAAAAU3MPOB0jN6CcB9oS/S5KPwzIAAAAVAA"
                        "AAAAAAAAAAAAAVA2QP8QvKYUK4CdtUS8ix3BQAAAAWAAAAAAAA"
                        "AAAAAAAWr8Dzxk0iCDRKW0vGQNEcqVoAAAAXAAAAAAAAAAAAAA"
                        "AXtmBrCnoCjI5LFHBdGl1YgKkAAAAYAAAAAAAAAAAAAAAYQ37C"
                        "SNBlDUOMjwSuEW9IMZsAAAAZAAAAAAAAAAAAAAAZFblf6wXcba"
                        "1K9UoMelgXB2AAAAAaAAAAAAAAAAAAAAAaRkhuC6Z2IndOzVoA"
                        "KMhq618AAAAbAAAAAAAAAAAAAAAbk2xy91C8AZ95olGSQDsqqB"
                        "oAAAAcAAAAAAAAAAAAAAAcNcinOzBhfLJ0wRUE6fV7auoAAAAd"
                        "AAAAAAAAAAAAAAAd3XEGUEX4svWSP9KtBC3v3D4AAAAeAAAAAA"
                        "AAAAAAAAAeFGrkwpRhYK7XUdZ8MJlES5MAAAAfAAAAAAAAAAAA"
                        "AAAfLkjlFYZoP0BkCGjFfm91qaoAAAAgAAAAAAAAAAAAAAAgHi"
                        "2qpRdVZCIEqQZqudSvfsYAAAAhAAAAAAAAAAAAAAAh7XpuyzK3"
                        "jrNlqk1z58t82vsAAAAiAAAAAAAAAAAAAAAiOI74jps/JqPZcc"
                        "X467sGtcYAAAAjAAAAAAAAAAAAAAAj4z8T6WnUpD43U/OnrLi+"
                        "094AAAAkAAAAAAAAAAAAAAAkL6FH5aOiNFtzWKxNj66+4wQAAA"
                        "AlAAAAAAAAAAAAAAAl57Gyxw44NMj9BXgAvEtEGn0AAAAmAAAA"
                        "AAAAAAAAAAAmmMVB+3iOBqPqKUJBpNK8tb4AAAAnAAAAAAAAAA"
                        "AAAAAnLmMwJmdVQfVMhwqKWGih81EAAAAoAAAAAAAAAAAAAAAo"
                        "mVJSJRFYS04t9iCCai0emk8AAAApAAAAAAAAAAAAAAApwCCRA9"
                        "z39R7NWADqsdLZoNkAAAAqAAAAAAAAAAAAAAAq5XaUizsv2PF8"
                        "UJvIr4cJfaIAAAArAAAAAAAAAAAAAAArA/QwjpPKNOUgrrYvYb"
                        "vdnzgAAAAsAAAAAAAAAAAAAAAsy1PiK5CMXUzRJx3CBoV9algA"
                        "AAAtAAAAAAAAAAAAAAAt8wt6cjL7Vf9PeRw6qdt9LL8AAAAuAA"
                        "AAAAAAAAAAAAAuLs+cGjx3J09ftazhUeMFqikAAAAvAAAAAAAA"
                        "AAAAAAAvFDrgc6VKRKkraKIlLus8VdkAAAAwAAAAAAAAAAAAAA"
                        "AwP7/xaQ9CH6Q6btXVtkdm9gkAAAAxAAAAAAAAAAAAAAAxupv2"
                        "FG/Zgs0936k0rgcsIDwAAAAyAAAAAAAAAAAAAAAyavQLYrHkEE"
                        "xgPxUbt/vfbuwAAAAzAAAAAAAAAAAAAAAzMtwxLnqssaOrbBN4"
                        "7iC07zIAAAA0AAAAAAAAAAAAAAA06+TZXkgFRr7OXZaAJs2nV1"
                        "EAAAA1AAAAAAAAAAAAAAA1V1j4TPCEXEaRgCZ7jYe0aqEAAAA2"
                        "AAAAAAAAAAAAAAA25V+G5V1LucwE1DEjAHyvNLUAAAA3AAAAAA"
                        "AAAAAAAAA3/IZO0adn3+LFZ4XaQCtwddwAAAA4AAAAAAAAAAAA"
                        "AAA4IkEVGVxSbVb9Mr/UifVLFaAAAAA5AAAAAAAAAAAAAAA5vz"
                        "4t0fCOxv18jd17F8Dx0j0AAAA6AAAAAAAAAAAAAAA69Uuvr8AK"
                        "EuDi2i2K5CkPVj4AAAA7AAAAAAAAAAAAAAA7awFnbvdm1YILhK"
                        "YSDP6UC3UAAAA8AAAAAAAAAAAAAAA8n5mdN5YgiOrPTdsRvkxi"
                        "oZEAAAA9AAAAAAAAAAAAAAA9U1WdxSc4rC/Xj4kZkSmPTWIAAA"
                        "A+AAAAAAAAAAAAAAA++lfacqdiulf/XLg7xv/ZgaEAAAA/AAAA"
                        "AAAAAAAAAAA/L1PLKnbcfGIEbrBBCZQGLtcAAABAAAAAAAAAAA"
                        "AAAABAp5JtK66yhtJhiQlro2zH+R8AAABBAAAAAAAAAAAAAABB"
                        "CpkQSoXjGtEzdGBDDhbss/EAAABCAAAAAAAAAAAAAABCYQiHrK"
                        "9MfUlep5LJMqCPYhoAAABDAAAAAAAAAAAAAABD/vhTvqXEZWJR"
                        "IX7rLZcnoRwAAABEAAAAAAAAAAAAAABEba8jHDEjkmBYDCPcBw"
                        "I6+cf/////AAAARQAAAAAAAAAAAAAARQAAAAC1uN37SrCiVmcl"
                        "lzaYPnEj",
        .datakey_b64 = "wElcw7jHSJ5f/aQpQyxuodFP3OgmxBnO1LNZPn+QU2U=",
        .comment = "29. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=1",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4K3m8tPW6+GZbv2h6l/Zog57SL5sT9o50Bf9FbObk18gAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwHMATBwGsO"
                        "+itTfXkCARCAO2quKOuXQ1vgTLsWWcF5Xxta5xGkziCmXh3MjZ"
                        "z7fg9Rh9+uM7giP9yGqpLPhws29+QCSDc+U+MjbjvPAgAAABBK"
                        "cTTOB2n0NhpGIjqX6asWzqnVxGL9ElHDsIADOwl25HBnjqaKG2"
                        "LS5Yb+aVyMJW4AAAABAAAAAAAAAAAAAAABabtPdgY42AWzHXmW"
                        "92NiQzrnvQV9OrG3UN89DTZZ/tkAAAACAAAAAAAAAAAAAAACXd"
                        "1zoo32cOde25/kpfepcMB8JCqFeYQRFlyc0YrKJf0AAAADAAAA"
                        "AAAAAAAAAAADKLae04FNWjljylpTTZPVdmAMQ2WoHKzMPC1qns"
                        "WZHvAAAAAEAAAAAAAAAAAAAAAEBt6stQeuur0FKyYK9bR1K6+s"
                        "Jn/q8wB8gajT1pxb+Xb/////AAAABQAAAAAAAAAAAAAABQAAAA"
                        "XwamnjgyqZoZJjJMf8KLi4WFC5AzM=",
        .datakey_b64 = "E4ocDFKJ9JGz2dXyOBNqh9atsl6ceVqoftZzhiTAVK8=",
        .comment = "30. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=16",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4gAA7pUhGfkfy82zd66QV7oEpgAY/d0PQv+69MJwcZaQAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAz2OsdsmlWW"
                        "A/LqJscCARCAO/Zfy5nh0mNvvn4WKkjt6cTqBl/tAmmJKHyxt9"
                        "orNTGGoTRAyUy4EA5A794sqU0AVXiSP3y4GIcg3GT9AgAABACc"
                        "uZNYrK2pO/AtSUAL495ZtuouZUHtgi66pbyqaJkJglijsti80C"
                        "wWoVmBdkCk+2f/////AAAAAQAAAAAAAAAAAAAAAQAAAEdqhQog"
                        "nTmY0tGmRPwKMMi5WhdUab5fEA4aqCR5QaKp9J4JnTdrqepBxk"
                        "Z1KWjlmiUnqCGyTIPhKhTMTYFztz3cphx85xe1raLWByDQbPSa"
                        "D/6FOEixwLY=",
        .datakey_b64 = "CcR2nrT/kcO4xJDogk5djrW6fSbjErxmXf9anzG5kSU=",
        .comment = "31. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=1024",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4L2S0PjlT+XA5n5U65oi/3NDRjFAuzOzfc8ceMbAh5DYAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFzanM1TklJblNo"
                        "M2RrVmtyQmlxSkhXK2dNVzV5eWx5elNUbVprVUZMOTBiS09kMm"
                        "dhUUM2N1k4WmpGTktNVmY0Zz09AAEAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEB"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDEoy6kj/pFN3NU5iXQIBEIA7X7fjiNBdtg"
                        "eYDNAoe/DcVQVw5rgnJS9VqnSp0KlF0Km8a/ZzXCgYBb00WwTn"
                        "s4vcxq0rZwVL4DkULToBAAAAAJB7d2YxM9LBEXbzT3LVQHP3yo"
                        "tU2Y2n6pLQmYeo8bMe7YU6Q4zMaICWf7u2RP6NQAAAAAAAAAAA"
                        "AAAAAQAAAAAAAABLCoBohy10UfWSBVipyqTKUw6ur/9jPvsWSw"
                        "w4CaQ7mtjQ+CY9xwO10H6zRIxnq3bR43iYHM8d0clSV4k6dNet"
                        "1Y2HJt1bFXnuuY3rdAxH/Iee//SvqvVjcOwNsABnMGUCMQCY+A"
                        "HrGu/0hAy6dWbX+zVTu97+MUfSl8NcMmTNCKhtwcxKHnTQZlFE"
                        "c7Qzu7A6iDMCMBReZ6xwJp1h8fzYyZ9m50XDwG/jzx/v+lRbGV"
                        "ulEjVdfdWvyYx+GAkNJEEQaBVZwQ==",
        .datakey_b64 = "p7jVbJV7IWyZ+VKrPIMcPRU0kdAqQxOtCLDYwuRps84=",
        .comment = "32. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4G59FPxp4eCwrZrzjP0zIia9+Xmv+DdaTCNUj9UdyT5UAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREEvS3ljdHpsZXJl"
                        "Y3lKVkprbmhaWWxJVTFvMUwyRVFhTW5kR2crWXVaM20xUGhKc2"
                        "FhMzNTb3VkZXVkVnBTdWZVQT09AAEAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEB"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDFIoc1AQR8OC2l7aXwIBEIA7pAVMPn0bKi"
                        "cv2GF06mdRGqr6IZctNrW869kDcgeqXsC/IhAiyA3brWRtHO8l"
                        "DcCx6TOui4cUBl5LbRkCAAAAAVgQnJX1I3I/gwqHN9WBR+wkto"
                        "vleZA+FcMfZK53PD4HJNlQi+hiddz7BzZ2x8dz1QAAAAEAAAAA"
                        "AAAAAAAAAAH6hiLwm61FKyZIVJ5Dgr1acgAAAAIAAAAAAAAAAA"
                        "AAAAIpjg7By8dC2ZHjZ/S9cSOvzwAAAAMAAAAAAAAAAAAAAAOb"
                        "NSUiZWX8lwFtNHjqrvX4sgAAAAQAAAAAAAAAAAAAAAR6gBWPSh"
                        "2VN9MuwZnPQvaQggAAAAUAAAAAAAAAAAAAAAVV/wH26SAUDlq7"
                        "BAKUnORfWQAAAAYAAAAAAAAAAAAAAAZDS7iasEfC8+aNvMKUvx"
                        "mfQgAAAAcAAAAAAAAAAAAAAAcw8DfzpbUpdLE+kMhvjIa5ggAA"
                        "AAgAAAAAAAAAAAAAAAjkp+B7/MjQZYfgm2sBVmHMdAAAAAkAAA"
                        "AAAAAAAAAAAAmFsLrFImT9XKNX0tVRBQqLQQAAAAoAAAAAAAAA"
                        "AAAAAAq6EEV0z6hlVJp3AL30LehixwAAAAsAAAAAAAAAAAAAAA"
                        "saxNNz/sYHvhgCR0PQQkH04wAAAAwAAAAAAAAAAAAAAAxjJldq"
                        "NlEu6ITLCakDw0gY3gAAAA0AAAAAAAAAAAAAAA172WI0cwhEQs"
                        "biQWgoIFa/fQAAAA4AAAAAAAAAAAAAAA6+3tSZUsawS/rrPYmv"
                        "cdtFkQAAAA8AAAAAAAAAAAAAAA8Z81209RGv8Z0QimqPThyerw"
                        "AAABAAAAAAAAAAAAAAABCByy4MtjCN3Wy9Nn9hsI9vbAAAABEA"
                        "AAAAAAAAAAAAABFbFO/gycPiUcTkHzh4klXH5gAAABIAAAAAAA"
                        "AAAAAAABLCAvSTNXaxkORs1mrELxX1CgAAABMAAAAAAAAAAAAA"
                        "ABP46C4rpY0w6O3UnQw120osSAAAABQAAAAAAAAAAAAAABRoXl"
                        "UncJeXgYFMsh9wcXGGpwAAABUAAAAAAAAAAAAAABVPH6Nx42nt"
                        "HZl0WPSDaVBpNAAAABYAAAAAAAAAAAAAABborIPmvL4hkpO8cs"
                        "nyVszbDQAAABcAAAAAAAAAAAAAABfoAarvLJzMo9LzvplYJ0z7"
                        "UgAAABgAAAAAAAAAAAAAABh6xAbHnaHgvRianxFxcoi91wAAAB"
                        "kAAAAAAAAAAAAAABmUGdoPiR+LaqleN4ruQ5n8UgAAABoAAAAA"
                        "AAAAAAAAABrbke10pO7tdGjMk9Spwp7EJwAAABsAAAAAAAAAAA"
                        "AAABuJ0hqaSzY1TBNDSLeqdqRq3wAAABwAAAAAAAAAAAAAABwy"
                        "Tl6mHYrnSAfqOfgWn2s5nwAAAB0AAAAAAAAAAAAAAB0eWf7GVK"
                        "xO4LEkI9XtFFk2NQAAAB4AAAAAAAAAAAAAAB6nAa1DdDySbukA"
                        "7at+XH6aLwAAAB8AAAAAAAAAAAAAAB/qAJOKUQalSgU75GGbM1"
                        "yAzgAAACAAAAAAAAAAAAAAACCCBw4vb8imgRzdnUMlXhHe6QAA"
                        "ACEAAAAAAAAAAAAAACEkbHaqI9rRCi9MarTGSodhEQAAACIAAA"
                        "AAAAAAAAAAACIvmgnKEYHpqc+dJ/0sCrM/mQAAACMAAAAAAAAA"
                        "AAAAACN8QFGdt8QEg+URLecB1EbO4QAAACQAAAAAAAAAAAAAAC"
                        "QjIcpT9lnC5UA3pjns4TX+CAAAACUAAAAAAAAAAAAAACXBE7fy"
                        "5ZCePzy3STbn2dUIsgAAACYAAAAAAAAAAAAAACZHRnjw/lca05"
                        "LLkLydCeSxNwAAACcAAAAAAAAAAAAAACeuAnxpbbZPLdU0IJ3w"
                        "hFoowQAAACgAAAAAAAAAAAAAACgzFy0vZNVUgH9isdIhO4GCrw"
                        "AAACkAAAAAAAAAAAAAACnTg3PoHTMN4673nGAkCGzRmwAAACoA"
                        "AAAAAAAAAAAAACo3WM6OCtVhXhHjgVK92UXX9QAAACsAAAAAAA"
                        "AAAAAAACuEMGasWfG7QC6WtNju/PoTCgAAACwAAAAAAAAAAAAA"
                        "ACzq1QxIxYOR43+vDzYfnTSAMAAAAC0AAAAAAAAAAAAAAC3wrV"
                        "Uo0rXbuJVjsV1vt0hGUAAAAC4AAAAAAAAAAAAAAC7MQHqvQChi"
                        "a9xJbr81eakxlgAAAC8AAAAAAAAAAAAAAC8X0rpxvH52BMZliw"
                        "38/O//DQAAADAAAAAAAAAAAAAAADCE31B8VdUDWhcQD8Kmq+3e"
                        "fQAAADEAAAAAAAAAAAAAADHq2/OHej6R9ISLLOpVGzCtCQAAAD"
                        "IAAAAAAAAAAAAAADLkIimNGhmvQsAaD3DVPIJGBAAAADMAAAAA"
                        "AAAAAAAAADMPZv0nxfJWZguIWSRXsfyglQAAADQAAAAAAAAAAA"
                        "AAADSAb9IJ7bLeZEImaGCTiVrn6QAAADUAAAAAAAAAAAAAADVF"
                        "t5mGXVMjaWv6WYuEAZjdqQAAADYAAAAAAAAAAAAAADYI+SbSqh"
                        "vd39VgFMer790y0wAAADcAAAAAAAAAAAAAADcXdXGZ2k+t49sa"
                        "tVhz9LOcWgAAADgAAAAAAAAAAAAAADgPW3aT6KKizLm2A73ogc"
                        "9oZwAAADkAAAAAAAAAAAAAADkG2dTERDi0cbqvMD501HGdqwAA"
                        "ADoAAAAAAAAAAAAAADoVf9abCyD7/0Mkm2ySzCwuHwAAADsAAA"
                        "AAAAAAAAAAADsnLxuSiKLU8RY2Aq4rYKHK3QAAADwAAAAAAAAA"
                        "AAAAADzGGZwcbZ2e61lGPhOOhpyffgAAAD0AAAAAAAAAAAAAAD"
                        "0lruywXjsHw/iYThi+a5zCHQAAAD4AAAAAAAAAAAAAAD5JnSIp"
                        "bIhsgJhfWBbcx/1EoAAAAD8AAAAAAAAAAAAAAD/9RL67BjPpPB"
                        "r+Djfu0ushVwAAAEAAAAAAAAAAAAAAAEANjJvUtnvY4sObpmQV"
                        "MRsiAgAAAEEAAAAAAAAAAAAAAEFZo1rTPAjWN3oBgdr9k+yC2g"
                        "AAAEIAAAAAAAAAAAAAAEIa9b4AZlHCy1rFI+iA1I3jgAAAAEMA"
                        "AAAAAAAAAAAAAEPwE8D9vvJIjwXdAmOfb2Bb2AAAAEQAAAAAAA"
                        "AAAAAAAETOLOQQ0DoTcu+P38lYEHhw0wAAAEUAAAAAAAAAAAAA"
                        "AEXRh443rHCOlQVzE6QkY+JLSwAAAEYAAAAAAAAAAAAAAEax2z"
                        "eECli3YAMJeWV8vkTjUgAAAEcAAAAAAAAAAAAAAEesScoaij1e"
                        "duqyFJI8XZ3r4AAAAEgAAAAAAAAAAAAAAEi1g3Ph6isEe84fJD"
                        "23O66uowAAAEkAAAAAAAAAAAAAAEkAtev7EfCHIbP1hUPSa+AP"
                        "mgAAAEoAAAAAAAAAAAAAAEpTmxls3i5+3RLS3Kzm3gRR2wAAAE"
                        "sAAAAAAAAAAAAAAEs1RBRPyLdVra0D7j9upDsjcwAAAEwAAAAA"
                        "AAAAAAAAAEyktVQw/UXx5rxR8CDOe86nUgAAAE0AAAAAAAAAAA"
                        "AAAE09Lc+gByhxZDXZ6Bu4/Es4LwAAAE4AAAAAAAAAAAAAAE6d"
                        "J2VUGaNSQmTQ2mGUFagNewAAAE8AAAAAAAAAAAAAAE//JhhaZg"
                        "GShFlVu+xyl5yuLv////8AAABQAAAAAAAAAAAAAABQAAAAAC2N"
                        "8l4GZZsE0yShavVhe0QAZzBlAjAEPZdxRS4gWPjqXXHLWN4nEG"
                        "HkLHVDnSe1EkadA7267tE0w04BezAnOLkPS9ipwBYCMQCJG7fY"
                        "h6YP81Nzaw4445SHEo0TNOhk/tkUjvsUq3bNB9dGuHZaQQ6Bqb"
                        "MQvG4VxEE=",
        .datakey_b64 = "ApPHw6yUnnWea70HYU9vvgxIiWuk7gMb7lMXR21W8Kk=",
        .comment = "33. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=1",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4Cri6kFSyB84mx+wt4qgx2ExzbBbVhfDaCweFtJmyyawAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF5N09CbzhYUW9l"
                        "c0treU1WZHJiZi9TQ3F5MDNtdjU2Y3hkS1ZOa2JoRUU2VWpGYn"
                        "g0VzUzZGkrRytsRTVSMjdOdz09AAEAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEB"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDM5cn+Y/7Y9bQ29WGwIBEIA7TG4kG9yQfL"
                        "tTTbvL/NkE9PWXfFT12F9/0zlKLgcHn3ba1Jv8LE7kd5bGR4WZ"
                        "Bj4/yZ6QOVOlZKdhU8ECAAAAEOFIohyrSsm7hQfZ7DbWFJhEn6"
                        "uZoCO7Q0VBqGMiH//ROcwUJFQI0V1re2sMD2gKXwAAAAEAAAAA"
                        "AAAAAAAAAAHDBPMQUYEwG2fKOjLSy5TzIsJuX6yGSneyX7N8tw"
                        "kLgAAAAAIAAAAAAAAAAAAAAALHIwp6ifqKY4ST4ht1YPK3tMgV"
                        "KbMA2MGnxO/KASWUZQAAAAMAAAAAAAAAAAAAAAPe7atR4Zuw7r"
                        "ws2Lq3LNDx9HQLgtbxXg2Uop5GGCrMYAAAAAQAAAAAAAAAAAAA"
                        "AATvARGcM3tkX8Rfw+Z2OG+66JDtoVCeTwwrIKZ0SBYd1gAAAA"
                        "UAAAAAAAAAAAAAAAXz16pY+9hY6+4aSLMNcMp1uNrLUsSOlZzO"
                        "qpK+Fugsnv////8AAAAGAAAAAAAAAAAAAAAGAAAAAEpDJdbidG"
                        "3or3xz3g+j9a0AZzBlAjEA9LQRM/AjRx+cYDuMo0NnK9ZmAaWb"
                        "oUmeRJqQjdaOTLtdaZfn2hDBV6gBsQIaQ2jbAjBP+cYTlMcb2d"
                        "guFKM0DJRr9bQGcoAp45aIm1IgSSt8/4zvBHAuE38TYu5FFgpn"
                        "bd0=",
        .datakey_b64 = "VJP9B8uCnNxrdEtV8kPaU5pjiK7xL/CgTkLycy1kU+U=",
        .comment = "34. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=16",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4vg62vd1Hv5VE+VGjBa7oc3FPvQTDk7ZguY9GiKGulTkAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFrR0hBdmFSNVB2"
                        "bWxRbnQzWXpZQWRKWFlrTUdBMmZLNjJzU1VwSC9jbzd0elM1ZT"
                        "dXekFuZzNhTlVQU3dLSk15dz09AAEAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEB"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDMpcqA4MbfdI8aAUOgIBEIA7R9FnrsMXuh"
                        "PlFikOTW3aKzvEOVWNQPtpeOCLfU+aZhGKhSmkCYomwyogxt3F"
                        "X3nrjfC3T9qCgCR7Z+UCAAAEAIhjUi358MWbu7FHlNnUMi9LI+"
                        "65mze4uaZKVo24z2vFwi6+JWRjsiDczse9YIuKCP////8AAAAB"
                        "AAAAAAAAAAAAAAABAAAAUtmGBbD+Xwh+szMmNcT+da9ik8xoO5"
                        "QTFdDp2SrPulgAb1GaXcbrSCH/3wGjFqbcP0X8x2t9mwuZk7LL"
                        "+bRme5aYdgy8KsTH4QoYQEVaiVGdV54L2jkURaCut8W4puj0S/"
                        "qAAGcwZQIwb9jj+9a4kwMeg2TIaBnDlFsRFNz4pru5AkTjm785"
                        "jJRzxqmNo+8/AxyHjdLpPL3uAjEAnyBFU1XaaHI7+iRblm/9Fd"
                        "bdgvxcvN4aqhjvujvZTbZncE9IMALJviNMHxV9wa0g",
        .datakey_b64 = "B83FiL96eWtjx7o/RNhfeJfHS5n0cGIaPNZjS52TV1w=",
        .comment = "35. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=1024",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4yNblPxh8dEafsUL5bpyJNqiqn8p+y/7AXcHUbywUVpwAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxa70VQY6/+"
                        "Av/OLD8CARCAO/v5YAqSmoWIuYyYXF1mrgXuRMSCIan5ihnGlB"
                        "fWLeayEd35vc+XCXUPkFhkq518ngB09ul3bHPgvphgAgAACAAZ"
                        "8+mwxDWarFDhqjHmpnIy2q2R80WwF9lAWy4ZCmei64JGBkBhGG"
                        "4U4vF+Qh4TOMb/////AAAAAQAAAAAAAAAAAAAAAQAAAAmoJ2RC"
                        "TnS8yT+k0RTr16lJzJ/ISzKB1paB",
        .datakey_b64 = "vfPpEnCooy3XFzxt/4vPIZ2i7ec07PiYmasAU0PT7JY=",
        .comment = "36. [Python ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=2048",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV47ifhy2pEjH4uPOG+7E9js5isde/lfQ99SPOJ6k44gtMAfw"
                        "ADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFqZGJtM2lxSXFP"
                        "QWQyT3QzQjZuWGpTYVN2aWZrTmtDMzNpUEpJMjZYNEo0KzRBRG"
                        "J4VnFRTndOcjljOFgzcUZOZz09AAVrZXlfYQAHdmFsdWVfYQAF"
                        "a2V5X2IAB3ZhbHVlX2IAAQAHYXdzLWttcwBLYXJuOmF3czprbX"
                        "M6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEt"
                        "ZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjC"
                        "deMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8Bgkq"
                        "hkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQ"
                        "MEAS4wEQQM8OlFmmVp8XwQLrSrAgEQgDsFOqtWv5PZxNNeWRRG"
                        "iaTgSHUr69mvDLohdL88CEkTaiAExVWhByMUSpvbbJW9TUmNJW"
                        "kCd3nhGl90SQIAAAgA+9+06T874sHO44BxZyxznHnDFdH9j1qo"
                        "Z/XIjE1IZeBnGjkqNF7n262O13osDfHh/////wAAAAEAAAAAAA"
                        "AAAAAAAAEAAAAJ7Vzzk9nJuGI6j4rF7n3eLTTMWmU0rH25jABn"
                        "MGUCMQDiZmYTwm7emvFwByAYHYXJQUYfc5FfSpjUp7nNQz9gCb"
                        "oKc3O8z0E/+832YqPQLj8CMA5LI5IofS9NBy5j4GpNpu7CWqUZ"
                        "HDWAEXDjGydjpCBL5Rw9IrrjuIJ81S48w/cY1Q==",
        .datakey_b64 = "27Mr50n9EYgz/iYs6a1xpgQJaw0u4bPtxI2gUE08Dkg=",
        .comment = "37. [Python ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=2048",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4wjhFuoHhF6np5UvxBujGNCGe8CcoCsePw7aXzeLgH8wAfw"
                        "ADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREE4dXY0S0lYWlIw"
                        "TWhwUm5kQ3ZZK0p1elRRcStqVWxacnBWMHM5RXFNV0ZjaFRBd0"
                        "FIVXdIK2tOSzA5S3BBQnkwdz09AAVrZXlfYQAHdmFsdWVfYQAF"
                        "a2V5X2IAB3ZhbHVlX2IAAQAHYXdzLWttcwBLYXJuOmF3czprbX"
                        "M6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEt"
                        "ZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjC"
                        "deMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8Bgkq"
                        "hkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQ"
                        "MEAS4wEQQMvsueY9q2K9SdGKfuAgEQgDvLQ5OljOCV1/YH/tYz"
                        "l8WF+LGPRRj07YoY41t9XjjzZkhjH6nhZfY+QO8CLSM8ut1UDc"
                        "jsiHMc8wAPPQEAAAAArqoSW/LCsWqA2PzItFUJsyDF/wAPCbMz"
                        "c6YuAdKnWXvUPTIdnPA3H7jAmRegjNLnAAAAAAAAAAAAAAABAA"
                        "AAAAAAAAkdnEdnIYuM46iNVFb59YSGI28tcMvNOTHdAGcwZQIx"
                        "AItH5NgTud0q8MNvhktGLyG2UDTJHxiDJ5yZs5Tuc9Vlxl/t2c"
                        "GFdJqp1vopF4RxhAIwToqh7JWjG24wQ3t9mXSLpoNwJL2Wotrz"
                        "nE/XIcjW4SZLtjETsQGq+yF92XR6s8Ur",
        .datakey_b64 = "qApow0AClB0e1zK5u4NLs33LpEbugfQgH5JTYXn2MvY=",
        .comment = "38. [Python ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4SKFdV3T67xu9VbyFL2tA8QdxcqAxzgD7Eh13p8M5cMcAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxln6D0fSs0"
                        "n3QylqECARCAO49ROJ2rH9g3yzoyD2O3CqMCM+vYYYf9LdgxgW"
                        "Spic1pBiox441RgiXNTen/xE8KH5KFApq7UxF6cVmUAgAACAAV"
                        "pe6A8Ntdm2I23PgG9j0YsKxz+5AzUVADJtE5fhaQktSunzx3GU"
                        "VkkZNV9X66ONn/////AAAAAQAAAAAAAAAAAAAAAQAAAAnLTOSn"
                        "7ir+xUizlogMTuv032ic0uHdwvS+",
        .datakey_b64 = "bg8qt1PWj3LyfQbmltjoZyFAm/Pgs0Ft8YvOwhzEO78=",
        .comment = "39. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; frameSize=2048",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR489rpKG1gc7jEIpNVoPmEidpm/S6/mMNmpo5DUPtjfvoAAA"
                        "ABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4"
                        "OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS"
                        "01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSt"
                        "o+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQ"
                        "AwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwj+RmdJoCG"
                        "vYKswYkCARCAO4v0/pYT9NN+9UN1a+Wwt4ME2TQUXCGDLktXwO"
                        "PTrpzzKbsdey847gJLMscis/PnhJFjIInSl7YXTs4sAQAAAAD4"
                        "mNRyy2Ilyp28lKHdEvDtfZG56XuJjZUp1tPYfAy0EmkB6jixZ5"
                        "UADkWCIjCQLYkAAAAAAAAAAAAAAAEAAAAAAAAACaZigN09HSXK"
                        "B3hv/nlrI7juPtl66ZV0Pz8=",
        .datakey_b64 = "jUopPfY/IoBzCxwLOuIAMcPIgV8CqHbET1rRxbVLYZc=",
        .comment = "40. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; unframed",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4vafj1mv/vUetSfKzMMMdBBhex4G16PjlJ8K+9OByS6IAHg"
                        "ACAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgABAAdhd3Mt"
                        "a21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwOD"
                        "MzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNi"
                        "YjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6"
                        "C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZI"
                        "hvcNAQcBMB4GCWCGSAFlAwQBLjARBAyI8tQDiO0m7qOfNg0CAR"
                        "CAO+VgyLtxT+Eb02elXBaCQ3cz55+SvPcqHHUXXuCX8JaWXgq0"
                        "InC8zDfr6KfTc1itDb86rBsOLEoyAPT9AgAACAASKDlK/F3PcV"
                        "npZ/IV03tWNmt60wMWMIxI40arC9KXaLV0vuEnPh6RTqoptrrW"
                        "ITT/////AAAAAQAAAAAAAAAAAAAAAQAAAAkCrP0akjzj2aPe8q"
                        "r9NwhMueXE1c27YMph",
        .datakey_b64 = "MZv4plYYs6q9TOExQ5P+HeH3NOKIRXjiLVv2Vj8LSxQ=",
        .comment = "41. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; frameSize=2048",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgR4bhUk0J5Af3Nq/UkQD6Dqx3ru9xUluYP6CW+318aF9hUAHg"
                        "ACAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgABAAdhd3Mt"
                        "a21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwOD"
                        "MzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNi"
                        "YjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6"
                        "C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZI"
                        "hvcNAQcBMB4GCWCGSAFlAwQBLjARBAw6iQ92YNQm0DM9RKACAR"
                        "CAO/86abwJHCx3jzUuMGFStBVCKwXla3beFh0tsco5I9yuNKah"
                        "zl60HDzG08n3szNFsCFgSg39Mg47ABiXAQAAAADoJEHTCZXi5+"
                        "RjdcDY/SDrBc4gcsZIJ7SjSj1D3hsUf6rJ1u+UKD8iaMm0Ae6g"
                        "VX0AAAAAAAAAAAAAAAEAAAAAAAAACQaK024+LpXF6tV/ekHQSm"
                        "rC4ZABZTZqUJY=",
        .datakey_b64 = "67b7K61ls7BZ76vRXY1Ydl13KvFEtF44Lb8V1A+qaWk=",
        .comment = "42. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; unframed",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4kRpnmOGf7OG3OqrPlL6SqR4ZO7nvoOOfkB/NOmJ9VJUAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFtN1Z3eG12OGho"
                        "c0kxL2VEUThMTzVna2dyTGw5Y3MvZE5QWWRsL1laMkxjamxCdl"
                        "dxRzVwb2FWaytLM0psejFBUT09AAEAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEB"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDOj+C2KslbEZcT2PSgIBEIA7K6QwakePtQ"
                        "0xW+Ip/0cNi7DkMqwTGORmv5asamzXbUKz28JNCInaqW14aIuu"
                        "wwsm0z3+809CE+ko72MCAAAIAG4FL0GhcP4Vc8AUVzjbvzYhLi"
                        "km6htqY5pQtOEbLI8vwrg/XVgcMv7hpEMsgmnr1v////8AAAAB"
                        "AAAAAAAAAAAAAAABAAAACWk9CHIOP9+CMH6UJi1wsxwKA2UiLb"
                        "PKa0oAZzBlAjBN+Qychto+YKgiEJUtrFuWjEs7M+V8UCim4+pN"
                        "9FtZmiEgchHyQnMSCyvV95kHtFsCMQDs0M1Bjg3s2bfLKsiH+h"
                        "kJePl+Hasn8bNwPShA54u1eXCnm1mv8+yjNLy19DDXSl4=",
        .datakey_b64 = "N1FQDxFaNrglCmz/yTTVfZVh36k3KvgeKpZuHrvdCbg=",
        .comment = "43. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frameSize=2048",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV48AP2Janq1bcZ1DrZJtaJNM24UZD9UX7R2/yP+4OzLuMAXw"
                        "ABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF4UWphQ1NXQzkz"
                        "SWJZV3ZLbFhNUWlybFEyZVBBeUlRcUJ6am1zK1NtZVo4d0txaz"
                        "JyS1lPVHJMOFFqWVVzMVR3Zz09AAEAB2F3cy1rbXMAS2Fybjph"
                        "d3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNT"
                        "M3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEB"
                        "AHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH"
                        "4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJ"
                        "YIZIAWUDBAEuMBEEDDD5mSvuYzwT9/eJ9QIBEIA7vnyXsGXnLU"
                        "RceBmqLlK8soxg/cIstDKW1XCI0OfGY4yhYjjr0l9XwAu0clOY"
                        "rJdpwJNjYAz8uIpnXs0BAAAAANDc3n2TAsoULoixfm5jipiQ2q"
                        "ABoB2KBteVpJ1xvjgRidbCTV7O5ggCOjqfRt8YcgAAAAAAAAAA"
                        "AAAAAQAAAAAAAAAJ7o9NINW0Q1jdL6PfMKn+f6izn2bU5QJOcQ"
                        "BnMGUCMBF6eRMvcIRQ+7kb/dxKaFem2GFa0vnpoBclaik6SWH1"
                        "/J+qSyIwskpIG8yrWvkjDwIxAOSeqMPZX2uZbbExbyWZUE1/rC"
                        "1f4JqA0wFTkWPTEIkfu9YCo2ZhdZrVm1xeqjmr0g==",
        .datakey_b64 = "xhOuDy6HPNHtVzACWDor5m2KyT69vFGsv3wRP0OMJG0=",
        .comment = "44. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4wPGtUdkHghbL8J2/2JO48DSSazj5Z2HLrY1NsW0XKnUAew"
                        "ADAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgAVYXdzLWNy"
                        "eXB0by1wdWJsaWMta2V5AERBMnJLdFI0Q082NWtiWEttaVlQY3"
                        "VXZEk0aXJ2OUJZWGV5RXJzdFp6VzU1eDZNOGFBZTJSR1hnZjF5"
                        "Q1Y2cmZiZGc9PQABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy"
                        "13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRj"
                        "LTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCX"
                        "QWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3"
                        "DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLj"
                        "ARBAxM5zuF0GHdLiOWtw0CARCAOyep7YpLEJtixgbgjRDDP15f"
                        "fP7C9Sma9PC1T55rcDTBKiArCbu4zH849ZPSzc+zeeHcSDc1LZ"
                        "OtCFUGAgAACADpb8LgUoW6cWWE7VLLY1Yp/w3r9hw02ZPVxxXc"
                        "4WrPwp6oUhEnIzWOoXWnOF+KX5//////AAAAAQAAAAAAAAAAAA"
                        "AAAQAAAAnFSX0svHUHX5oYM5mZeQH+lI/B9cYxRX2EAGcwZQIw"
                        "TWCrBLIkRLWjWpKmdbpKSexC4w7UJlR0SMud5kym5+Hs9+VFho"
                        "3PblnEQ5qXtS5RAjEApDNPjapvgGdC5t+ti8L6NFjFhrsc1fRO"
                        "pUiNno2A86+QjLUQe0BuRoPmHlPWl0ez",
        .datakey_b64 = "vxGKyd1THdpAdVHmYdoLwsY7Vw9C6pGQLhdVwarE0Lw=",
        .comment = "45. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frameSize=2048",
        .should_succeed = true
    },
    {
        .ciphertext_b64 =
                        "AgV4NIrbgvJHnrCNOqOP2FRfO9GITBLJd8xbEvhJu3WNCUAAew"
                        "ADAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgAVYXdzLWNy"
                        "eXB0by1wdWJsaWMta2V5AERBd1NZQ21RODYybmVKRUlBRU9Ycz"
                        "RqVGIzVlBLL1pwbWtOSkR6eGFRaVVjR0VTUGxZekd1K3cxQkt2"
                        "cjhIOWlYemc9PQABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy"
                        "13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRj"
                        "LTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCX"
                        "QWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3"
                        "DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLj"
                        "ARBAwcMP008tCOAHWwKMQCARCAO6JddAzG8rjYhkiifNg+u9CV"
                        "3YrfgX3/WJLQVfruPM8rAY6b0h1CA59q9287F3wAz4TdBDvOJx"
                        "25OjL0AQAAAAB/DPmV33Jz8DtfV/0gBSp21AE5JTdylNEwTsUc"
                        "nHyofXYjPvkvq6aJCt3gWOLtnSkAAAAAAAAAAAAAAAEAAAAAAA"
                        "AACaX0vpCBWsCd0SKJWqWLPmqKgG2g961qBIoAZzBlAjEAo3oA"
                        "liRCOvhExMFaAtgdHJhguUdlEKE8HYGEbCWILUcmY3pdQEZWF9"
                        "av1eMGOT5uAjBeKCuCrzI496vqYC3eChefw4J7bGrWTcUZVwCb"
                        "ijJV/VehvV8WoH1kds8esTZl24Y=",
        .datakey_b64 = "k/f3Ora/LfrKWi/gAkrVUJy7BTVeotHdFR4fTPk2Lc8=",
        .comment = "46. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed",
        .should_succeed = true
    },
