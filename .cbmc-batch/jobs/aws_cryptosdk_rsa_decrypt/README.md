# Expected Coverage 

0.97 (232 lines out of 239 statically-reachable lines in 45 functions reached)
0.90 (232 lines out of 259 statically-reachable lines in 52 statically-reachable functions)

## Expected Functions with Incomplete Coverage 

(4/6) aws_raise_error_private:	
(2/7) EC_KEY_free: ec_key is always NULL, so limited coverage is expected. 
(0/4) nondet_compare: 
(0/2) BN_clear_free: function never reached, part of chain originating with EC_KEY_free
(0/2) BN_free: function never reached, part of chain originating with EC_KEY_free
(0/2) bignum_is_valid: function never reached, part of chain originating with ec_key_is_valid
(0/4) EC_GROUP_free: function never reached, part of chain originating with EC_KEY_free
(0/3) ec_group_is_valid: function never reached, part of chain originating with ec_key_is_valid
(0/3) ec_key_is_valid: ec_key is always NULL, so this is never called from evp_pkey_is_valid