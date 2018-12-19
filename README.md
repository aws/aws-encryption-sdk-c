## AWS Encryption SDK C

The AWS Encryption SDK for C provides easy-to-use envelope encryption in C,
with a data format compatible with the [AWS Encryption SDKs for Java and
Python](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

**This library is currently under public preview**. Feel free to check out the
code and give it a spin, but be aware that the APIs might change as we get
closer to release. We'd love to hear your feedback on the APIs before they're
fully nailed down.

## Dependencies

The only direct dependencies of this code are OpenSSL 1.0.2 or higher and
[aws-c-common](https://github.com/awslabs/aws-c-common). You will also need
a C compiler and CMake 3.9 or higher.

In order for the AWS Encryption SDK for C to work with [KMS](https://aws.amazon.com/kms/)
you will also need a direct dependency on [aws-sdk-cpp](https://github.com/aws/aws-sdk-cpp).
This will also require a C++ compiler. aws-sdk-cpp has dependencies on libcurl, aws-c-common,
[aws-checksums](https://github.com/awslabs/aws-checksums), and
[aws-c-event-stream](https://github.com/awslabs/aws-c-event-stream). Those three
AWS libraries must be built in exactly that order.

You need to compile the dependencies as either all shared or all static libraries.
The C libraries default to static library builds and the aws-sdk-cpp defaults to
a shared library build. We will use all shared library builds in our examples, by
using the cmake argument `-DBUILD_SHARED_LIBS=ON`. You can change them to static library builds
by just changing `ON` to `OFF`.

Once you have built each dependency, you should `make install` it so it can be picked
up by the next build. If desired, you can set the installation to happen in an arbitrary
directory with `-DCMAKE_INSTALL_PREFIX=[path to install to]` as an argument to cmake,
and then later builds will need `-DCMAKE_PREFIX_PATH=[path dependencies were installed in]`.

You can also use `-DOPENSSL_ROOT_DIR=[path to where openssl was installed]` to make
the build use a particular installation of OpenSSL.

If these dependencies were installed in the default location for library
installations on your system, cmake may be able to find them without these
defines.

## Building on Amazon Linux

The following recipe should work with a new Amazon Linux instance, and installs
everything in the standard directories in /usr/local.

For best results, create the EC2 instance with an instance profile that at a
minimum has KMS permissions for Encrypt, Decrypt, and GenerateDataKey for
at least one KMS CMK in your account. You will not need any other AWS
permissions to use the AWS Encryption SDK for C.

Start by installing a few basic dependencies:

    sudo yum install -y gcc-c++ openssl-devel libcurl-devel git

The yum repo has an old version of CMake, so download CMake 3.9 or later from [their
website](https://cmake.org/) and make sure cmake is in your path.

The following is a bash command to download, build, and install the C library
dependencies in the correct order. We are pinning to known working versions of
each of the libraries. Run from the directory you want to do the build in.

    for i in aws-c-common,v0.2.0 aws-checksums,v0.1.0 aws-c-event-stream,v0.1.0 ;
    do IFS=',' read dep ver <<< "$i" ;
    git clone --branch $ver git@github.com:awslabs/${dep}.git ;
    mkdir ${dep}/build ; cd ${dep}/build ;
    cmake -DBUILD_SHARED_LIBS=ON .. ;
    make && sudo make install ; cd ../.. ; done

Now you should be able to build aws-sdk-cpp:

    git clone --branch 1.7.21 git@github.com:aws/aws-sdk-cpp.git
    mkdir aws-sdk-cpp/build ; cd aws-sdk-cpp/build
    cmake -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" ..
    make && sudo make install ; cd ../..

Finally, you can build this package. We give one extra argument to compile the examples.

    git clone git@github.com:awslabs/aws-encryption-sdk-c.git
    mkdir aws-encryption-sdk-c/build ; cd aws-encryption-sdk-c/build
    cmake -DBUILD_SHARED_LIBS=ON -DAWS_ENC_SDK_EXAMPLES=1 ..
    make && sudo make install

If you have gotten this far, you should be in the build directory with a working
build of the AWS Encryption SDK for C. Run `make test` to run the tests,
or run `examples/string_encrypt_decrypt` with an argument of the ARN of your
KMS CMK in order to run a small piece of example code. You can see the source code
of the example in the examples subdirectory of the main aws-encryption-sdk-c
directory, one level up from where you are now.

### Tips and tricks

When building aws-sdk-cpp, you can save time by only building the subcomponents we need:

    cmake -DBUILD_ONLY="kms" [path to aws-sdk-cpp source]

To enable debug symbols, set `-DCMAKE_BUILD_TYPE=Debug` at initial cmake time,
or use `ccmake .` to update the configuration after the fact.

## License

This library is licensed under the Apache 2.0 License. 
