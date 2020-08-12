# Memory safety proof for aws_cryptosdk_md_update

This proof harness attains 67% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `EVP_PKEY_free`:

    * pkey field of EVP_MD_CTX is always NULL, therefore there is nothing to free

Some functions are simply unreachable:

* `BN_clear_free`

    * Only function call is from a chain starting at the unreachable block of EVP_PKEY_free

* `BN_free`

    * Only function call is from a chain starting at the unreachable block of EVP_PKEY_free

* `bignum_is_valid`

    * Only function call is from a chain starting at an unreachable condition in evp_md_ctx_is_valid

* `EC_GROUP_free`

    * Only function call is from a chain starting at the unreachable block of EVP_PKEY_free

* `EC_KEY_free`

    * Only function call is from a chain starting at the unreachable block of EVP_PKEY_free

* `ec_group_is_valid`

    * Only function call is from a chain starting at an unreachable condition in evp_md_ctx_is_valid

* `ec_key_is_valid`

    * Only function call is from a chain starting at an unreachable condition in evp_md_ctx_is_valid

* `evp_pkey_is_valid`

    * Only function call is from a chain starting at an unreachable condition in evp_md_ctx_is_valid