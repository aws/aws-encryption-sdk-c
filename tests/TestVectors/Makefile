test_vectors: *.cpp *.h
	g++ -g -ggdb --std=c++14 -o test_vectors -I../../include/ *.cpp \
	-I/opt/homebrew/include/ -L/opt/homebrew/lib/ \
	-I../../install/include/ -L../../install/lib/ -I ../../aws-encryption-sdk-cpp/include/ \
	../../build-aws-encryption-sdk-c/Debug/libaws-encryption-sdk.dylib \
	../../build-aws-encryption-sdk-c/aws-encryption-sdk-cpp/Debug/libaws-encryption-sdk-cpp.dylib \
	-laws-cpp-sdk-core -laws-cpp-sdk-kms -laws-c-common -lcrypto
	install_name_tool -add_rpath ../../build-aws-encryption-sdk-c/Debug/ test_vectors
	install_name_tool -add_rpath ../../build-aws-encryption-sdk-c/aws-encryption-sdk-cpp/Debug/ test_vectors

decrypt_dafny: test_vectors
	./test_vectors decrypt --manifest-path ./from-dafny --manifest-name decrypt-manifest.json

encrypt: test_vectors
	rm -rf local
	mkdir -p local
	./test_vectors encrypt --manifest-path ./from-dafny --decrypt-manifest-path ./local

decrypt: test_vectors
	./test_vectors decrypt --manifest-path ./local --manifest-name decrypt-manifest.json


hold:
	../../build-aws-encryption-sdk-c/Debug/libaws-encryption-sdk.dylib
	../../build-aws-encryption-sdk-c/aws-encryption-sdk-cpp/Debug/libaws-encryption-sdk-cpp.dylib
