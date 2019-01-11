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
you will also need the [AWS SDK for C++](https://github.com/aws/aws-sdk-cpp).
This will require a C++ compiler and libcurl.

For best results when doing a C++ build, do not install aws-c-common directly, but simply
build and install the AWS SDK for C++, which will build and install aws-c-common for you.
If you install aws-c-common before building the AWS SDK for C++, this will fool the
AWS SDK for C++ install logic, and you will be forced to install several other dependencies
manually. The minimum supported version of the AWS SDK for C++ is 1.7.31.

You need to compile both the AWS Encryption SDK for C and its dependencies as either all
shared or all static libraries. We will use all shared library builds in our examples, by
using the cmake argument `-DBUILD_SHARED_LIBS=ON`. You can change them to static library
builds by just changing `ON` to `OFF`.

Once you have built each dependency, you should `make install` it so it can be picked
up by the next build.

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

Do a KMS-only build of the AWS SDK for C++:

    git clone git@github.com:aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" ../aws-sdk-cpp
    make && sudo make install ; cd ..

Now you can build the AWS Encryption SDK for C.

    git clone git@github.com:awslabs/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DBUILD_SHARED_LIBS=ON ../aws-encryption-sdk-c
    make && sudo make install ; cd ..

## Building on Ubuntu

Install the needed dependencies with:

    sudo apt-get update
    sudo apt-get install -y libssl-dev cmake g++ libcurl4-openssl-dev zlib1g-dev

Then just follow the Amazon Linux installation instructions above, starting with
the AWS SDK for C++ build.

## Tips and tricks

When building aws-sdk-cpp, you can save time by only building the subcomponents we need:

    cmake -DBUILD_ONLY="kms" [path to aws-sdk-cpp source]

To enable debug symbols, set `-DCMAKE_BUILD_TYPE=Debug` at initial cmake time,
or use `ccmake .` to update the configuration after the fact.

If desired, you can set the installations to happen in an arbitrary
directory with `-DCMAKE_INSTALL_PREFIX=[path to install to]` as an argument to cmake.
`-DCMAKE_PREFIX_PATH` will cause a cmake package to look for dependencies in the
directory you specify, but `-DCMAKE_INSTALL_PREFIX` will also set the prefix path,
so there is no need to use both of these arguments.

You can also use `-DOPENSSL_ROOT_DIR=[path to where openssl was installed]` to make
the build use a particular installation of OpenSSL.

## License

This library is licensed under the Apache 2.0 License. 
