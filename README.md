# AWS Encryption SDK for C

The AWS Encryption SDK for C is a client-side encryption library designed to make it easy for
everyone to encrypt and decrypt data using industry standards and best practices. It uses a
data format compatible with the AWS Encryption SDKs in other languages. For more information on
the AWS Encryption SDKs in all languages, see the [Developer Guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

Also, see the [API documentation](https://aws.github.io/aws-encryption-sdk-c/html/) for the AWS Encryption SDK for C.

## Dependencies

The only direct dependencies of this code are OpenSSL 1.0.2 or higher or 1.1.0 or higher and
[aws-c-common](https://github.com/awslabs/aws-c-common) v0.3.15. You will also need
a C compiler and CMake 3.9 or higher.

To integrate with [KMS](https://aws.amazon.com/kms/) the AWS Encryption SDK for C also requires
the [AWS SDK for C++](https://github.com/aws/aws-sdk-cpp), a C++ compiler, and libcurl.

For best results when doing a build with KMS integration, do not install aws-c-common directly.
Build and install the AWS SDK for C++, which will build and install aws-c-common for you (see the C++ SDK dependancies
 [here](https://github.com/aws/aws-sdk-cpp/blob/master/third-party/CMakeLists.txt#L18)). If
you install aws-c-common before building the AWS SDK for C++, this will fool the AWS SDK for
C++ install logic, and you will be forced to install several other dependencies manually. Version 1.7.163 of the 
AWS SDK for C++ is supported by version v1.0.1 of the AWS Encryption SDK for C.

You need to compile both the AWS Encryption SDK for C and its dependencies as either all
shared or all static libraries. We will use all shared library builds in our examples by
using the cmake argument `-DBUILD_SHARED_LIBS=ON`. You can change them to static library
builds by just changing `ON` to `OFF`.

Once you have built each dependency, install it so it can be picked up by the next build.

### If you are working on an EC2 instance, regardless of operating system

For best results, create an EC2 instance with an instance profile that at a
minimum has KMS permissions for Encrypt, Decrypt, and GenerateDataKey for
at least one KMS CMK in your account. You will not need any other AWS
permissions to use the AWS Encryption SDK for C.

## Build recipes

We will demonstrate some simple build recipes for Linux, Mac, and Windows operating systems.

The Linux and Mac recipes install everything in the standard directories in /usr/local. The
Windows recipe installs everything in an install directory placed at the directory you are in
when you start the build process. To change the installation directory, if desired, see the Tips
and Tricks section at the end of this README.

You can do (Option 1) a C and C++ build, which will include integration with KMS, or you can do
(Option 2) a C only build, which will not include integration with KMS. In places where
the recipes diverge, these will be labeled as (Option 1) and (Option 2). Follow one of the two
options, but not both, depending on which installation you want to do.

### Building on Amazon Linux

This recipe should work with a brand new Amazon Linux instance. Start in the directory where
you want to do your build.

#### Amazon Linux: (Option 1) C and C++ build dependencies

Run the following:

    sudo yum update
    sudo yum install -y openssl-devel git gcc-c++ libcurl-devel

The yum repo has an old version of CMake, so download CMake 3.9 or later from [their
website](https://cmake.org/) and make sure cmake is in your path.

Both aws-sdk-cpp and aws-c-common are required, but the installation of aws-sdk-cpp will install
aws-c-common for you.

Do a KMS-only build of the AWS SDK for C++. If you want to use the AWS SDK for C++ for
other AWS services, you can omit the `-DBUILD_ONLY="kms"` argument, but the build will take much longer.

    git clone https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp
    make && sudo make install ; cd ..

Now skip to the "Amazon Linux: Build and install the AWS Encryption SDK for C" section below.

#### Amazon Linux: (Option 2) C only build dependencies

Run the following:

    sudo yum update
    sudo yum install -y openssl-devel git gcc

The yum repo has an old version of CMake, so download CMake 3.9 or later from [their
website](https://cmake.org/) and make sure cmake is in your path.

Now build and install aws-c-common:

    git clone https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -DBUILD_SHARED_LIBS=ON ../aws-c-common
    make && sudo make install ; cd ..

#### Amazon Linux: Build and install the AWS Encryption SDK for C

    git clone https://github.com/aws/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DBUILD_SHARED_LIBS=ON ../aws-encryption-sdk-c
    make && sudo make install ; cd ..

You have successfully built and installed the AWS Encryption SDK for C.

### Building on Ubuntu

These instructions have been tested on brand new Ubuntu EC2 instances. You should also
be able to build on Ubuntu operating systems that are not in EC2, but you will need to
manually configure AWS credentials if you are using KMS. Start in the directory where
you want to do your build.

#### Ubuntu: (Option 1) C and C++ build dependencies

    sudo apt-get update
    sudo apt-get install -y libssl-dev cmake g++ libcurl4-openssl-dev zlib1g-dev

Both aws-sdk-cpp and aws-c-common are required, but the installation of aws-sdk-cpp will install
aws-c-common for you.

Do a KMS-only build of the AWS SDK for C++. If you want to use the AWS SDK for C++ for
other AWS services, you can omit the `-DBUILD_ONLY="kms"` argument, but the build will take much longer.

    git clone https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp
    make && sudo make install ; cd ..

Now skip to the "Ubuntu: Build and install the AWS Encryption SDK for C" section below.

#### Ubuntu: (Option 2) C only build dependencies

    sudo apt-get update
    sudo apt-get install -y libssl-dev cmake gcc

Now build and install aws-c-common:

    git clone https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -DBUILD_SHARED_LIBS=ON ../aws-c-common
    make && sudo make install ; cd ..

#### Ubuntu: Build and install the AWS Encryption SDK for C

    git clone https://github.com/aws/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DBUILD_SHARED_LIBS=ON ../aws-encryption-sdk-c
    make && sudo make install ; cd ..

You have successfully built and installed the AWS Encryption SDK for C.

### Building on Mac

We recommend setting up [Homebrew](https://brew.sh/) to install some build tools.
Once it is set up, run the following:

    brew install openssl@1.1 cmake

(Note: Installing the AWS SDK for C++ through Homebrew does a full build, which
takes much longer than the KMS-only build. For these reasons, we recommend doing a source
build of the AWS SDK for C++ yourself, as we will demonstrate below.)

Start in the directory where you want to do your build.

#### Mac: (Option 1) C and C++ build dependencies

Both aws-sdk-cpp and aws-c-common are required, but the installation of aws-sdk-cpp will install
aws-c-common for you.

Do a KMS-only build of the AWS SDK for C++. If you want to use the AWS SDK for C++ for
other AWS services, you can omit the `-DBUILD_ONLY="kms"` argument, but the build will take much longer.

    git clone -b v1.7.163 https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -G Xcode -DBUILD_SHARED_LIBS=ON -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp 
    xcodebuild -target install ; cd ..

Now skip to the "Mac: Build and install the AWS Encryption SDK for C" section below.

#### Mac: (Option 2) C only build dependencies

Build and install aws-c-common:

    git clone -b v0.3.15 https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -G Xcode -DBUILD_SHARED_LIBS=ON ../aws-c-common
    xcodebuild -target install ; cd ..

#### Mac: Build and install the AWS Encryption SDK for C

Brew installed OpenSSL 1.1 to a place that is not picked up by default so we will
set the directory manually in our build.

    git clone https://github.com/aws/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -G Xcode -DBUILD_SHARED_LIBS=ON -DOPENSSL_ROOT_DIR="/usr/local/opt/openssl@1.1" ../aws-encryption-sdk-c 
    xcodebuild -target install; cd ..

You have successfully built and installed the AWS Encryption SDK for C.

### Building on Windows

**Note**: _see the docker-images folder for some Windows build recipes that automate many of theses steps_

Start by installing Visual Studio version 15 or later with the Windows Universal C Runtime and
[Git for Windows](https://git-scm.com/download/win).


Use the **x64 Native Tools Command Prompt** for all commands listed here. Run the following commands in the
directory where you want to do the build and installation.

    mkdir install && mkdir build && cd build
    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg && .\bootstrap-vcpkg.bat
    .\vcpkg install curl:x64-windows openssl:x64-windows && cd ..

#### Windows: (Option 1) C and C++ build dependencies

Both aws-sdk-cpp and aws-c-common are required, but the installation of aws-sdk-cpp will install
aws-c-common for you.

Do a KMS-only build of the AWS SDK for C++. If you want to use the AWS SDK for C++ for
other AWS services, you can omit the `-DBUILD_ONLY="kms"` argument, but the build will take much longer.

    git clone https://github.com/aws/aws-sdk-cpp.git
    mkdir build-aws-sdk-cpp && cd build-aws-sdk-cpp
    cmake -DCMAKE_INSTALL_PREFIX=%cd%\..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DENABLE_UNITY_BUILD=ON -DBUILD_ONLY=kms -DCMAKE_TOOLCHAIN_FILE=%cd%\..\vcpkg\scripts\buildsystems\vcpkg.cmake -G Ninja ..\aws-sdk-cpp
    cmake --build . && cmake --build . --target install && cd ..

Now continue to "Windows: Build and install the AWS Encryption SDK for C" below.

#### Windows: (Option 2) C only build dependency

Build and install aws-c-common:

    git clone https://github.com/awslabs/aws-c-common.git
    mkdir build-aws-c-common && cd build-aws-c-common
    cmake -DCMAKE_INSTALL_PREFIX=%cd%\..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_TOOLCHAIN_FILE=%cd%\..\vcpkg\scripts\buildsystems\vcpkg.cmake -G Ninja ..\aws-c-common
    cmake --build . && cmake --build . --target install && cd ..

#### Windows: Build and install the AWS Encryption SDK for C

    git clone https://github.com/aws/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DCMAKE_INSTALL_PREFIX=%cd%\..\..\install -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_TOOLCHAIN_FILE=%cd%\..\vcpkg\scripts\buildsystems\vcpkg.cmake -G Ninja ..\aws-encryption-sdk-c
    cmake --build . && cmake --build . --target install && cd ..

You have successfully built and installed the AWS Encryption SDK for C.

## Doxygen Documentation

To build the documentation, you'll need [doxygen](http://www.doxygen.nl/) installed.  Check the [downloads](http://www.doxygen.nl/download.html) page 
or use your OS package manager.

Next, rerun the above cmake with a `-DBUILD_DOC="ON"` flag before building aws-encryption-sdk-c.

Finally, run either `make doc_doxygen` (Unix), `MSBuild.exe .\doc_doxygen.vcxproj` (Windows) or `xcodebuild -scheme doc_doxygen` (Mac) to generate the documentation.

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
