include ../Makefile

goto: proofs.goto
	goto-instrument proofs.goto proofs.goto

proofs.goto: aws-c-common
	cd ../../..; \
	goto-cc .cbmc-batch/hdr_zeroize.c aws-c-common/source/byte_buf.c \
    aws-c-common/source/common.c aws-c-common/source/error.c \
    -Iinclude -Iaws-c-common/include -o .cbmc-batch/jobs/hdr_zeroize/proofs.goto \
    --function hdr_zeroize_verify
