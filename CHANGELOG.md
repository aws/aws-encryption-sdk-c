# Changelog


## 1.0.1 -- 2019-10-10
* Modified Doxygen config file to generate dependency graphs [#376](https://github.com/aws/aws-encryption-sdk-c/pull/376)
* Ran reformat [#426](https://github.com/aws/aws-encryption-sdk-c/pull/426)
* Strengthen memory_order for refcount_down [#433](https://github.com/aws/aws-encryption-sdk-c/pull/433)
* Update PR template [#391](https://github.com/aws/aws-encryption-sdk-c/pull/391)
* Refreshing the clang-format file and checking the version [#430](https://github.com/aws/aws-encryption-sdk-c/pull/430)
* Fix MultiKeyringNew proof so it runs again. [#444](https://github.com/aws/aws-encryption-sdk-c/pull/444)
* Windows build fixes [#446](https://github.com/aws/aws-encryption-sdk-c/pull/446)
* OSX build steps and README updates [#453](https://github.com/aws/aws-encryption-sdk-c/pull/)

## 1.0.0 -- 2019-05-20
* Changed links from awslabs to aws 
* Initial stable release 

## 0.2.0 -- 2019-05-13
* Added API function to make session from keyring
* Added API function to make caching CMM from keyring
* Added `_from_cmm` to end of `aws_cryptosdk_caching_cmm_new` function name
* Changed `aws_cryptosdk_session_get_algorithm` to `aws_cryptosdk_session_get_alg_id`
* Fixed HKDF bug

## 0.1.2 -- 2019-02-28
* Fixed empty string bug on git version of KMS user agent
* Local tests only by default
* Fix of MAP_ANONYMOUS issue for older Linuxes

## 0.1.1 -- 2019-02-21
* Fixed cmake bug regarding git version of KMS user agent
* Added CBMC header file needed by newer aws-c-common versions

## 0.1.0 -- 2019-02-05
* Initial public release
