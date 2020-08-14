# Memory safety proof for aws_cryptosdk_enc_ctx_clone

This proof harness attains 95% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `aws_hash_table_put`

    * Edge cases never reached. was_created is always false and we never try and put an item in a full table

* `aws_string_eq`

    *  a !=b and neither a nor b are even NULL

* `aws_hash_iter_is_valid`

    *  Data structure invariants always hold