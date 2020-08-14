# Memory safety proof for aws_cryptosdk_enc_ctx_init

This proof harness attains 91% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `aws_hash_table_init`

    * s_update_template_size never returns an error

* `hash_table_state_is_valid`

    *  map is never NULL

* `aws_mem_calloc`

    *  Defensive overflow check always passes 

* `aws_round_up_to_power_of_two`

    *  n is always != 0 and <= SIZE_MAX_POWER_OF_TWO 

* `aws_add_u64_checked`

    *  Overflow never occurs 

* `aws_mul_u64_checked`

    *  Overflow never occurs 

* `hash_table_state_required_bytes`

    *  Overflow never occurs