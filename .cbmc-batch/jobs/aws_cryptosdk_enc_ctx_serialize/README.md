# Memory safety proof for aws_cryptosdk_enc_ctx_serialize

This proof harness attains 95% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code, instrinsic to the function.

Some functions contain unreachable blocks of code:

* `aws_cryptosdk_enc_ctx_serialize`

    * aws_array_list_get_at_ptr is never given an invalid index

* `hash_table_state_is_valid`

    *  map is never NULL

* `aws_array_list_is_valid`

    *  list is never NULL

* `aws_byte_buf_write_from_whole_string`

    *  Neither buf nor src are ever NULL

* `aws_add_u64_checked`

    *  Overflow never occurs 

* `aws_mul_u64_checked`

    *  Overflow never occurs 

* `aws_array_list_get_at_ptr`

    *  Index is always valid

* `hash_table_state_required_bytes`

    *  Overflow never occurs