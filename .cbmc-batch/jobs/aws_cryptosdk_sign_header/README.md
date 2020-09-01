# Memory safety proof for aws_cryptosdk_sign_header

This proof harness attains 92% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `assert_byte_buf_equivalence`

    * lhs==rhs never holds 
    * This assertion is called from the harness
    * To check desired property, header==old_header does not hold by design though assert_byte_buf_equivalence should

* `aws_cryptosdk_alg_properties_is_valid`

    * std_alg_props is never NULL as it is constructed from a aws_cryptosdk_alg_id

* `EVP_EncryptUpdate`

    * Variable out is always NULL as hard-coded in the aws_cryptosdk_sign_header function 