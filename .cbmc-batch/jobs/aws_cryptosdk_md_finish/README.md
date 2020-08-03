# Expected Coverage 

0.91 (73 lines out of 80 statically-reachable lines in 19 functions reached)
0.70 (73 lines out of 105 statically-reachable lines in 27 statically-reachable functions)

## Expected Functions with Incomplete Coverage 

(4/5) aws_cryptosdk_md_abort: md_context is never NULL
(4/6) aws_raise_error_private: 
(2/6) EVP_PKEY_free: pkey field of EVP_MD_CTX is always NULL, therefore there is nothing to free. 
(0/2) BN_clear_free: function never reached, part of chain originating with EVP_PKEY_free
(0/2) BN_free: function never reached, part of chain originating with EVP_PKEY_free
(0/2) bignum_is_valid: function never called, part of chain originating with evp_md_ctx_is_valid. 
(0/4) EC_GROUP_free: function never reached, part of chain originating with EVP_PKEY_free
(0/7) EC_KEY_free: function never reached, part of chain originating with EVP_PKEY_free
(0/3) ec_group_is_valid: function never called, part of chain originating with evp_md_ctx_is_valid. 
(0/3) ec_key_is_valid: function never called, part of chain originating with evp_md_ctx_is_valid. 
(0/2) evp_pkey_is_valid: Since pkey is always NULL, this is never called from evp_md_ctx_is_valid. 
