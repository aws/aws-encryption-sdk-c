# Memory safety proof for aws_cryptosdk_rsa_encrypt

This proof harness attains 100% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `EVP_PKEY_CTX_set_rsa_padding`:

    * RSA_X931_PADDING is never used