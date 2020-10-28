# Memory safety proof for aws_cryptosdk_enc_ctx_serialize

This proof harness attains 95% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code, instrinsic to the function.

Some functions contain unreachable blocks of code:

* `aws_cryptosdk_enc_ctx_serialize`

    * idx is always less than num_elems, so aws_array_list_get_at_ptr is never given an invalid index

* `hash_table_state_is_valid`

    *  map is never NULL as ensured by precondition that enc_ctx is valid hash table  

* `aws_array_list_is_valid`

    *  list is never NULL, as ensured by precondition when array list is initialized 

* `aws_byte_buf_write_from_whole_string`

    *  Neither buf nor src are ever NULL
    *  Precondition on the output parameter of aws_cryptosdk_enc_ctx_serialize ensures that buf is never NULL
    *  The generator array_list_item_generator ensures that src is never NULL (see comment of aws_cryptosdk_hash_elems_array_init_stub.c)

* `aws_add_u64_checked`

    *  Overflow never occurs as ensured by precondition in ensure_allocated_hash_table

* `aws_mul_u64_checked`

    *  Overflow never occurs as ensured by precondition in ensure_allocated_hash_table

* `aws_array_list_get_at_ptr`

    *  idx is always less than num_elems, so no AWS_ERROR_INVALID_INDEX is raised

* `hash_table_state_required_bytes`

    *  Overflow never occurs as ensured by precondition in ensure_allocated_hash_table