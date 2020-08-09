# Memory safety proof for aws_cryptosdk_sign_header

This proof harness attains 92% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* assert_byte_buf_equivalence
    * lhs==rhs never holds. 

* aws_cryptosdk_alg_properties_is_valid
    * std_alg_props is never NULL

* EVP_EncryptUpdate
    * Variable out is always NULL, so only that function behavior is explored. 