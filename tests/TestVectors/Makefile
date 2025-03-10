test_vectors: *.cpp *.h
	g++ -g -ggdb --std=c++14 -o test_vectors -I../../include/ \
	base64.cpp do_decrypt.cpp do_encrypt.cpp parse_encrypt.cpp parse_keys.cpp test_vectors.cpp \
	-I/opt/homebrew/include/ -L/opt/homebrew/lib/ \
	-I../../install/include/ -L../../install/lib/ -I ../../aws-encryption-sdk-cpp/include/ \
	../../build-aws-encryption-sdk-c/Debug/libaws-encryption-sdk.dylib \
	../../build-aws-encryption-sdk-c/aws-encryption-sdk-cpp/Debug/libaws-encryption-sdk-cpp.dylib \
	-laws-cpp-sdk-core -laws-cpp-sdk-kms -laws-c-common -lcrypto
	install_name_tool -add_rpath ../../build-aws-encryption-sdk-c/Debug/ test_vectors
	install_name_tool -add_rpath ../../build-aws-encryption-sdk-c/aws-encryption-sdk-cpp/Debug/ test_vectors
	install_name_tool -add_rpath ../../install/lib/ test_vectors

test_vectors_unix: *.cpp *.h
	g++ -g -ggdb --std=c++14 -o test_vectors -I../../include/ *.cpp \
	-I/opt/homebrew/include/ -L/opt/homebrew/lib/ \
	-I../../install/include/ -L../../install/lib/ -I ../../aws-encryption-sdk-cpp/include/ \
	../../build-aws-encryption-sdk-c/Debug/libaws-encryption-sdk.dylib \
	../../build-aws-encryption-sdk-c/aws-encryption-sdk-cpp/Debug/libaws-encryption-sdk-cpp.dylib \

decrypt_dafny: test_vectors
	./test_vectors decrypt --manifest-path ./from-dafny --manifest-name decrypt-manifest.json || exit 1

encrypt: test_vectors
	rm -rf local
	mkdir -p local
	./test_vectors encrypt --manifest-path ./from-dafny --decrypt-manifest-path ./local || exit 1

decrypt: test_vectors
	./test_vectors decrypt --manifest-path ./local --manifest-name decrypt-manifest.json || exit 1

clean:
	rm -f test_vectors