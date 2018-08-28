include ../Makefile

goto: proofs.goto
	goto-instrument proofs.goto proofs.goto

proofs.goto: aws-c-common config
	cd ../../..; \
    goto-cc .cbmc-batch/header_proofs.c source/header.c aws-c-common/source/byte_buf.c \
    aws-c-common/source/common.c aws-c-common/source/error.c .cbmc-batch/patches/memset_noset.c \
    -Iinclude -Iaws-c-common/include -I.cbmc-batch -o .cbmc-batch/jobs/aws_cryptosdk_hdr_size/proofs.goto \
    --function aws_cryptosdk_hdr_size_verify
