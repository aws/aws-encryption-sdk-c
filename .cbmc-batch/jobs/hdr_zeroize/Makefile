goto: proofs.goto
	goto-instrument proofs.goto proofs.goto

proofs.goto: aws-c-common config
	cd ../../..; \
	goto-cc .cbmc-batch/header_proofs.c source/header.c aws-c-common/source/byte_buf.c \
    aws-c-common/source/common.c aws-c-common/source/error.c \
    -Iinclude -Iaws-c-common/include -o .cbmc-batch/jobs/hdr_zeroize/proofs.goto \
    --function hdr_zeroize_verify

config:
	cd ../../; \
    cp config.h ../include/aws/cryptosdk/private/

aws-c-common:
	cd ../../..; \
    git clone https://github.com/awslabs/aws-c-common.git

clean:
	rm proofs.goto; \
	rm -rf ../../../aws-c-common
