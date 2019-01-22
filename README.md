# AWS Encryption SDK C

The AWS Encryption SDK for C provides easy-to-use envelope encryption in C,
with a data format compatible with the [AWS Encryption SDKs in other languages](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

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

Once you have built each dependency, you should install it so it can be picked
up by the next build.

### If you are working on an EC2 instance, regardless of operating system

For best results, create an EC2 instance with an instance profile that at a
minimum has KMS permissions for Encrypt, Decrypt, and GenerateDataKey for
at least one KMS CMK in your account. You will not need any other AWS
permissions to use the AWS Encryption SDK for C.

## Building on Linux and Mac

We will demonstrate some simple build recipes for Linux and Mac operating systems.
First follow the instructions for installing dependencies on your particular platform
then jump to the common installation instructions for all Linux and Mac systems.

These recipes install everything in the standard directories in /usr/local. See
the Tips and Tricks section at the end to change your installation directory if desired.

### Setting up dependencies on Amazon Linux

After logging into the instance, run the following:

    sudo yum update
    sudo yum install -y gcc-c++ openssl-devel libcurl-devel git

The yum repo has an old version of CMake, so download CMake 3.9 or later from [their
website](https://cmake.org/) and make sure cmake is in your path.

Now follow the "Common installation instructions for Linux and Mac" below.

### Setting up dependencies on Ubuntu

    sudo apt-get update
    sudo apt-get install -y libssl-dev cmake g++ libcurl4-openssl-dev zlib1g-dev

Now follow the "Common installation instructions for Linux and Mac" below.

### Setting up dependencies on Mac

We recommend setting up [Homebrew](https://brew.sh/) to install some build tools.
Once it is set up, run the following:

    brew install openssl@1.1 cmake

(Note: Installing the AWS SDK for C++ through Homebrew does a full build, which
takes much longer than the KMS-only build. For these reasons we recommend doing a source
build of the AWS SDK for C++ yourself, as in the common instructions below.)

Now follow the "Common installation instructions for Linux and Mac" below, but note that
the last step is slightly different on Mac.

### Common installation instructions for Linux and Mac

Start these instructions in whatever directory you want to do your build in. You can
do a C only build, which will not include integration with KMS, or you can do a
C and C++ build, which will include integration with KMS. Follow one of the two
subsections below, but not both.

#### (Option 1) C only build prerequisite: Install aws-c-common

    git clone https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -DBUILD_SHARED_LIBS=ON ../aws-c-common
    make && sudo make install ; cd ..

Now continue to "Install the AWS Encryption SDK for C" below.

#### (Option 2) C and C++ build prerequisite: Install the AWS SDK for C++

Both aws-sdk-cpp and aws-c-common are needed, but the installation of aws-sdk-cpp will handle
the installation of aws-c-common for you.

Do a KMS-only build of the AWS SDK for C++. If you want to use the AWS SDK for C++ for
other AWS services, you can omit the kms argument, but the build will take much longer.

    git clone https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp
    make && sudo make install ; cd ..

#### Install the AWS Encryption SDK for C

These directions will diverge slightly for Mac, because using brew we installed OpenSSL
in a place that will not be picked up by cmake by default.

On Linux (non-Mac) systems:

    git clone https://github.com/awslabs/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DBUILD_SHARED_LIBS=ON ../aws-encryption-sdk-c
    make && sudo make install ; cd ..

On Mac:

    git clone https://github.com/awslabs/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DBUILD_SHARED_LIBS=ON -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl\@1.1 ../aws-encryption-sdk-c
    make && sudo make install ; cd ..

## Building on Windows

### Setting up dependencies on Windows

Start by installing Visual Studio version 15 or later. To inherit the environment variables 
directly from Visual Studio, we recommend using the x64 Native Tools Command Prompt. 
You can run these instructions in whatever directory you want to do your build in.

    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg && .\bootstrap-vcpkg.bat
    .\vcpkg install curl:x64-windows openssl:x64-windows && cd ..


You can do a C only build, which will not include integration with KMS, or you can do a
C and C++ build, which will include integration with KMS. Follow one of the two
subsections below, but not both.

#### (Option 1)  C only build prerequisite: Install aws-c-common 

    git clone https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -DCMAKE_INSTALL_PREFIX=%cd%\..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_TOOLCHAIN_FILE=%cd%\..\vcpkg\scripts\buildsystems\vcpkg.cmake -G Ninja ..\aws-c-common
    cmake --build . && cmake --build . --target install && cd ..

Now continue to "Install the AWS Encryption SDK for C" below.

#### (Option 2)  C and C++ build prerequisite: Install the AWS SDK for C++

Both aws-sdk-cpp and aws-c-common are needed, but the installation of aws-sdk-cpp will handle
the installation of aws-c-common for you.

Do a KMS-only build of the AWS SDK for C++. If you want to use the AWS SDK for C++ for
other AWS services, you can omit the kms argument, but the build will take much longer.

    git clone https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DCMAKE_INSTALL_PREFIX=%cd%\..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DENABLE_UNITY_BUILD=ON -DBUILD_ONLY=kms -DCMAKE_TOOLCHAIN_FILE=%cd%\..\vcpkg\scripts\buildsystems\vcpkg.cmake -G Ninja ..\aws-sdk-cpp
    cmake --build . && cmake --build . --target install && cd ..

#### Install  the AWS Encryption SDK for C 

    git clone https://github.com/awslabs/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DCMAKE_INSTALL_PREFIX=%cd%\..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_TOOLCHAIN_FILE=%cd%\..\vcpkg\scripts\buildsystems\vcpkg.cmake -G Ninja ..\aws-encryption-sdk-c
    cmake --build . && cmake --build . --target install && cd ..

## Compiling your program using the AWS Encryption SDK for C

Once you have installed the AWS Encryption SDK for C, you are ready to start writing
your own programs with it.

When doing a C compilation (not using the KMS keyring) be sure to include the flags
``-lcrypto -laws-encryption-sdk -laws-c-common``.

When doing a C++ compilation (using the KMS keyring) be sure to include the flags
``-std=c++11 -lcrypto -laws-encryption-sdk -laws-encryption-sdk-cpp -laws-c-common -laws-cpp-sdk-kms -laws-cpp-sdk-core``.

In the examples directory of this repo are several self-standing C and C++ files.
On a successful build, these files will already be compiled in the examples subdirectory
of the build directory. Additionally, if you want a quick test that you have
built and installed the AWS Encryption SDK successfully, you can copy any of
the example files out of that directory and build them yourself.

Here are sample command lines using gcc/g++ to build a couple of the example files,
assuming that the libraries and headers have been installed where your system
knows how to find them.

    g++ -o string string.cpp -std=c++11 -lcrypto -laws-encryption-sdk -laws-encryption-sdk-cpp -laws-c-common -laws-cpp-sdk-kms -laws-cpp-sdk-core
    gcc -o raw_aes_keyring raw_aes_keyring.c -lcrypto -laws-encryption-sdk -laws-c-common

Note that the C++ files using the KMS keyring will require
you to make sure that AWS credentials are set up on your machine to run properly.

## Tips and tricks

When building aws-sdk-cpp, you can save time by only building the subcomponents needed
by the AWS Encryption SDK for C with `-DBUILD_ONLY="kms"`

The `-DENABLE_UNITY_BUILD=ON` option will further speed up the aws-sdk-cpp build.

To enable debug symbols, set `-DCMAKE_BUILD_TYPE=Debug` at initial cmake time,
or use `ccmake .` to update the configuration after the fact.

If desired, you can set the installations to happen in an arbitrary
directory with `-DCMAKE_INSTALL_PREFIX=[path to install to]` as an argument to cmake.

If you set `CMAKE_INSTALL_PREFIX` for the dependencies, when building the AWS
Encryption SDK for C you must either (1) set `CMAKE_INSTALL_PREFIX` to the same path,
which will cause it to pick up the dependencies and install to the same directory
or (2) set `CMAKE_PREFIX_PATH` to include the same path, which will cause it to pick
up the dependencies but NOT install to the same directory.

You can also use `-DOPENSSL_ROOT_DIR=[path to where openssl was installed]` to make
the build use a particular installation of OpenSSL.

By default the cmake for this project detects whether you have aws-sdk-cpp-core
and aws-sdk-cpp-kms installed in a place it can find, and only if so will it build
the C++ components, (enabling use of the KMS keyring.) You can override the detection
logic by setting `-DBUILD_AWS_ENC_SDK_CPP=OFF` to never build the C++ components or
by setting `-DBUILD_AWS_ENC_SDK_CPP=ON` to require building the C++ components (and
fail if the C++ dependencies are not found.)

## License

This library is licensed under the Apache 2.0 License. 