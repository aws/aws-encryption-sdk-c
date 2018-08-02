include ../Makefile

goto: proofs.goto
	goto-instrument proofs.goto proofs.goto

proofs.goto: aws-c-common config openssl
	cd ../../..; \
    goto-cc .cbmc-batch/cipher_proofs.c source/cipher.c aws-c-common/source/byte_buf.c \
    aws-c-common/source/common.c aws-c-common/source/error.c \
    -Iinclude -Iaws-c-common/include -I.cbmc-batch -o .cbmc-batch/jobs/aws_cryptosdk_derive_key/proofs.goto \
    --function aws_cryptosdk_derive_key_verify
