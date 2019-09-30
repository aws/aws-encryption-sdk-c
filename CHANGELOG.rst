*********
Changelog
*********

1.0.1 -- 2019-09-27
=================== 
* Merge pull request #376 from lucasmt/dependency-graph
* Merge pull request #426 from danielsn/reformat 
* Merge pull request #433 from nchong-at-aws/strengthen-atomic-refcount-down 
* Merge pull request #391 from johnwalker/prtemplate 
* Merge pull request #430 from dougch/clang_format_322 
* Fix MultiKeyringNew proof so it runs again. #444
* Windows build fixes #446

1.0.0 -- 2019-05-20
=================== 
* Changed links from awslabs to aws 
* Initial stable release 

0.2.0 -- 2019-05-13
===================
* Added API function to make session from keyring
* Added API function to make caching CMM from keyring
* Added "_from_cmm" to end of "aws_cryptosdk_caching_cmm_new" function name
* Changed "aws_cryptosdk_session_get_algorithm" to "aws_cryptosdk_session_get_alg_id"
* Fixed HKDF bug

0.1.2 -- 2019-02-28
===================
* Fixed empty string bug on git version of KMS user agent
* Local tests only by default
* Fix of MAP_ANONYMOUS issue for older Linuxes

0.1.1 -- 2019-02-21
===================
* Fixed cmake bug regarding git version of KMS user agent
* Added CBMC header file needed by newer aws-c-common versions

0.1.0 -- 2019-02-05
===================
* Initial public release
