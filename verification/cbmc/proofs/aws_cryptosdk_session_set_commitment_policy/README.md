# Memory safety proof for aws_cryptosdk_session_set_commitment_policy

This proof harness attains 40% code coverage.  The following comments explain
why the uncovered lines of code are unreachable code.

Some functions contain unreachable blocks of code:

* `aws_cryptosdk_priv_session_change_state`

    * Called from aws_cryptosdk_priv_fail_session with the argument "new_state" hard-coded to ST_ERROR. 
    * Only one case of the switch statement on "new_state" is therefore covered. 
    * Additionally, the current state is not ST_CONFIG from a conditional check in aws_cryptosdk_session_set_commitment_policy. 

Some functions are never reached:

* `abort`

    * abort is called from unexplored cases of aws_cryptosdk_priv_session_change_state.