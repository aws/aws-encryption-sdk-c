*********
Changelog
*********

0.1.0 -- 2019-02-05
===================
* Initial public release

0.1.1 -- 2019-02-21
===================
* Fixed cmake bug regarding git version of KMS user agent
* Added CBMC header file needed by newer aws-c-common versions

0.1.2 -- 2019-02-28
===================
* Fixed empty string bug on git version of KMS user agent
* Local tests only by default
* Fix of MAP_ANONYMOUS issue for older Linuxes

0.1.3 -- 2019-04-29
===================
* Added API function to make session from keyring
* Added API function to make caching CMM from keyring
* Added "_from_cmm" to end of "aws_cryptosdk_caching_cmm_new" function name
