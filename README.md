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
[aws-c-common](https://github.com/awslabs/aws-c-common) v0.3.0 or higher. You will also need
a C compiler and CMake 3.9 or higher.

In order for the AWS Encryption SDK for C to work with [KMS](https://aws.amazon.com/kms/)
you will also need the [AWS SDK for C++](https://github.com/aws/aws-sdk-cpp).
This will require a C++ compiler and libcurl.

For best results when doing a C++ build, do not install aws-c-common directly, but simply
build and install the AWS SDK for C++, which will build and install aws-c-common for you.
If you install aws-c-common before building the AWS SDK for C++, this will fool the
AWS SDK for C++ install logic, and you will be forced to install several other dependencies
manually. The minimum supported version of the AWS SDK for C++ is 1.7.36.

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

If you intend to use the KMS components to build the AWS Encryption SDK for C, you will have to build 
the AWS SDK for C++::

    git clone https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp
    make && sudo make install ; cd ..

If you donot intend to use the KMS components to build the AWS Encryption SDK for C, you will have to build
aws-c-common from source: 

    git clone https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -DBUILD_SHARED_LIBS=ON ../aws-c-common
    make && sudo make install ; cd ..


Now you can build the AWS Encryption SDK for C.

    git clone https://github.com/awslabs/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DBUILD_SHARED_LIBS=ON ../aws-encryption-sdk-c
    make && sudo make install ; cd ..

## Building on Ubuntu

Install the needed dependencies with:

    sudo apt-get update
    sudo apt-get install -y libssl-dev cmake g++ libcurl4-openssl-dev zlib1g-dev

Then just follow the Amazon Linux installation instructions above, starting with
the AWS SDK for C++ build.

## Building on Mac

The version of the AWS SDK for C++ in Homebrew is at the time of this writing
slightly too old to build with the AWS Encryption SDK for C. Furthermore,
installing it through Homebrew does a full build of the entire AWS SDK for C++, which
takes much longer than the KMS-only build. For these reasons we recommend doing a source
build of the AWS SDK for C++ yourself, as in the Linux instructions above.

Start by installing some dependencies.

    brew install openssl@1.1 cmake

Then build the AWS SDK for C++ and AWS Encryption SDK for C as above, but add the argument
`-DOPENSSL_ROOT_DIR=/usr/local/opt/openssl\@1.1` to the cmake line for the AWS Encryption
SDK for C.

## Building on Windows 

To install the AWS Encryption SDK for C in Windows, start by installing Visual Studio version 15 
or later. To inherit the environment variables directly from Visual Studio, we recommend using the Visual Studio
developer command prompt. You will also require a few basic dependencies: 

    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg && .\bootstrap-vcpkg.bat
    .\vcpkg integrate install
    .\vcpkg install curl:x64-windows openssl:x64-windows && cd ..

If you intend to use the KMS components to build the AWS Encryption SDK for C, you will have to build 
the AWS SDK for C++:
    
    git clone https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DCMAKE_INSTALL_PREFIX=..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DENABLE_UNITY_BUILD=ON -DBUILD_ONLY=kms -DCMAKE_TOOLCHAIN_FILE=..\vcpkg\scripts\buildsystems\vcpkg.cmake ..\aws-sdk-cpp
    msbuild.exe ALL_BUILD.vcxproj /p:Configuration=Release
    msbuild.exe INSTALL.vcxproj /p:Configuration=Release && cd ..

If you donot intend to use the KMS components to build the AWS Encryption SDK for C, you will have to build
aws-c-common from source: 

    git clone https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -DCMAKE_INSTALL_PREFIX=..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_TOOLCHAIN_FILE=..\vcpkg\scripts\buildsystems\vcpkg.cmake ..\aws-c-common
    msbuild.exe ALL_BUILD.vcxproj /p:Configuration=Release
    msbuild.exe INSTALL.vcxproj /p:Configuration=Release && cd ..

Now you can build the AWS Encryption SDK for C:

    git clone https://github.com/awslabs/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DCMAKE_INSTALL_PREFIX=..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_TOOLCHAIN_FILE=..\vcpkg\scripts\buildsystems\vcpkg.cmake ..\aws-encryption-sdk-c
    msbuild ALL_BUILD.vcxproj /p:Configuration=Release && cd ..

## Compiling your program using the AWS Encryption SDK for C

Once you have installed the AWS Encryption SDK for C, you are ready to start writing
your own programs with it.

When doing a C compilation (not using the KMS keyring) be sure to include the flags
``-laws-encryption-sdk -laws-c-common``.

When doing a C++ compilation (using the KMS keyring) be sure to include the flags
``-std=c++11 -laws-encryption-sdk -laws-encryption-sdk-cpp -laws-c-common -laws-cpp-sdk-kms -laws-cpp-sdk-core``.

In the examples directory are several self-standing C and C++ files that you can
compile and run directly. Note that the C++ files using the KMS keyring will require
you to make sure that AWS credentials are set up on your machine to run properly.

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
