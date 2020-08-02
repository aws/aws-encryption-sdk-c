# Expected Coverage 

0.91 (136 lines out of 149 statically-reachable lines in 25 functions reached)
0.91 (136 lines out of 149 statically-reachable lines in 25 statically-reachable functions)

## Expected Functions with Incomplete Coverage 

(8/9) assert_byte_buf_equivalence: lhs==rhs never holds. 

(8/9) aws_cryptosdk_alg_properties_is_valid: std_alg_props is never NULL

(7/17) EVP_DecryptUpdate: Variable out is always NULL, so only that function behavior is explored. 