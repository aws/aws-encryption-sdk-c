# Memory safety proof for aws_cryptosdk_enc_ctx_init

This proof harness attains 91% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code, instrinsic to the function.

Some functions contain unreachable blocks of code:

* `aws_hash_table_init`

    * s_update_template_size never returns an error due to choice of initial_size (10) in aws_cryptosdk_enc_ctx_init

* `hash_table_state_is_valid`

    *  map is never NULL, as ensured by precondition in source code. 

* `aws_mem_calloc`

    *  Defensive overflow check always passes 

* `aws_round_up_to_power_of_two`

    *  n is always != 0 and <= SIZE_MAX_POWER_OF_TWO  due to choice of initial_size (10) in aws_cryptosdk_enc_ctx_init

* `aws_add_u64_checked`

    *  Overflow never occurs adding initial size (10) to sizeof(struct hash_table_entry)

* `aws_mul_u64_checked`

    *  Overflow never occurs when multiplying initial size (10) by sizeof(struct hash_table_entry)

* `hash_table_state_required_bytes`

    *  Overflow never occurs when computing total number of bytes needed for a hash-table with "initial_size" slots. 