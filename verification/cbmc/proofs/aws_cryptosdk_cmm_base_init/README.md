# Memory safety proof for aws_cryptosdk_cmm_base_init

This proof harness attains 86% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `aws_atomic_priv_xlate_order`

    * aws_memory_order order is always aws_memory_order_seq_cst

Some functions are simply unreachable:

* `abort`

    * Memory order is never unknown, therefore only call to abort is not reached