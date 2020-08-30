# Memory safety proof for aws_cryptosdk_enc_ctx_clone

This proof harness attains 95% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code, instrinsic to the function. 
This proof assumes the representation of a hash_table given in aws_hash_table_no_slots_override.c 
(a hash-table that is not backed by any actual memory. It just takes non-det actions when given inputs). 
Otherwise the only assumption in the harness is for valid hash tables.

Some functions contain unreachable blocks of code:

* `aws_hash_table_put`

    * Edge cases never reached. 
    * was_created is always false, as hardcoded in the function aws_cryptosdk_enc_ctx_clone 
    * The MAX_NUM_ELEMS in a table is 4 as defined in the Makefile, meaning no overflow is possible. 

* `aws_string_eq`

    *  a !=b and neither a nor b are even NULL

* `aws_hash_iter_is_valid`

    *  Data structure invariants always hold