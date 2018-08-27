hdr_zeroize_patch:
	cd ../../..; \
	patch source/header.c .cbmc-batch/patches/hdr_zeroize.patch

config:
	cd ../../../; \
	cp .cbmc-batch/config.h include/aws/cryptosdk/private/config.h

aws-c-common:
	cd ../../..; \
	git clone https://github.com/awslabs/aws-c-common.git

openssl:
	cd ../../..; \
	git clone https://github.com/openssl/openssl.git; \
	cd openssl; \
	./config; \
	make; \
	make test; \
	make install

clean:
	rm proofs.goto; \
	rm -rf ../../../aws-c-common
