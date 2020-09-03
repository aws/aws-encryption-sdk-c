# Memory safety proof for aws_cryptosdk_edk_list_init

This proof harness attains 97% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `aws_array_list_is_valid`

    * list is never NULL as already ensured by a precondition 

* `aws_mul_u64_checked`

    * Multiplication never results in an overflow
    * The two arguments for mutliplication are the initial_item_allocation and sizeof(struct aws_cryptosdk_edk)
    * The initial_item_allocation is 4 as hardcoded by function aws_cryptosdk_edk_list_init