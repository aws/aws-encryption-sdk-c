# Memory safety proof for aws_cryptosdk_md_finish

This proof harness attains 99% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `aws_cryptosdk_md_abort`:

    * md_context is never NULL (part of satisyfing the md_context_is_valid precondition)