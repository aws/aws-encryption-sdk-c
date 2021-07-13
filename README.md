# AWS Encryption SDK for C

The AWS Encryption SDK for C is a client-side encryption library designed to make it easy for
everyone to encrypt and decrypt data using industry standards and best practices. It uses a
data format compatible with the AWS Encryption SDKs in other languages. For more information on
the AWS Encryption SDKs in all languages, see the [Developer Guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

Also, see the [API documentation](https://aws.github.io/aws-encryption-sdk-c/html/) for the AWS Encryption SDK for C.

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

See [Support Policy](./SUPPORT_POLICY.rst) for for details on the current support status of all major versions of this library.

## Building the AWS Encryption SDK for C with support for AWS KMS

We will demonstrate some simple build recipes for Linux, Mac, and Windows operating systems. These 
recipes assume a newly installed system with default installs of dependency packages.

The Windows instructions install everything in your current directory (where you run the build process). To change the installation directory, see the Tips and Tricks section at the end of this README.

The AWS Encryption SDK for C can be used with AWS KMS, but it is not required. If you want to build
a minimal version of the ESDK without AWS KMS support, see "Minimal C build without AWS KMS support", below.

For best results when doing a build with AWS KMS integration, do not install aws-c-common directly.
Build and install the AWS SDK for C++, which will build and install aws-c-common for you (see the C++ SDK dependencies
 [here](https://github.com/aws/aws-sdk-cpp/blob/master/third-party/CMakeLists.txt#L18)). If
you install aws-c-common before building the AWS SDK for C++, this will fool the AWS SDK for
C++ install logic, and you will be forced to install several other dependencies manually. Version 1.8.32 of the
AWS SDK for C++ is supported by version v1.0.1 of the AWS Encryption SDK for C.

### If you are working on an EC2 instance, regardless of operating system

For best results, create an EC2 instance with an instance profile that at a
minimum has AWS KMS permissions for Encrypt, Decrypt, and GenerateDataKey for
at least one AWS KMS CMK in your account. You will not need any other AWS
permissions to use the AWS Encryption SDK for C.

### Dependencies

1. OpenSSL 1.0.2 or newer, or 1.1.0 or newer
1. CMake 3.9 or newer
1. C/C++ compiler
1. aws-c-common, typically bundled with the AWS SDK for C++
1. The AWS SDK for C++ version 1.9.35 or newer

The AWS SDK for C++ and the AWS Encryption SDK for C share dependencies on OpenSSL, aws-c-common, and CMake. The AWS SDK for C++ has additional dependencies and prerequisites. See [AWS SDK for
C++: Getting Started](https://github.com/aws/aws-sdk-cpp#getting-started).

You need to compile the AWS Encryption SDK for C and its dependencies as either all
shared or all static libraries. 

To build shared libraries, specify the `-DBUILD_SHARED_LIBS=ON` flag to build
aws-c-common, the AWS SDK for C++, and the AWS Encryption SDK.

To build static libraries, specify the `-DBUILD_SHARED_LIBS=OFF` flag to build
aws-c-common, the AWS SDK for C++, and the AWS Encryption SDK.

### Linux Build Recipe

First, build the AWS SDK for C++. That will install the shared dependencies.

If you only need AWS SDK for C++ to use the AWS Encryption SDK, you have the option to build only the AWS KMS SDK.
Add the `-DBUILD_ONLY="kms"` flag and `-DBUILD_SHARED_LIBS=ON|OFF` to `cmake` in the instructions provided.

[Follow the AWS SDK for C++ build instructions](https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/setup-linux.html).

Now, build and install the AWS Encryption SDK for C:

    git clone --recurse-submodules https://github.com/aws/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake ../aws-encryption-sdk-c -DBUILD_SHARED_LIBS=ON
    make && sudo make install ; cd ..

### MacOS Build Recipe

[Homebrew](https://brew.sh) is a convenient way to get build tools for MacOS systems.

With Homebrew installed, run the following:

    brew install openssl@1.1 cmake

The AWS SDK for C++ can be installed with Homebrew, which will install the full AWS SDK. If you 
need the AWS SDK for C++ only to use the AWS Encryption SDK, you can build only the AWS KMS SDK.
See [these directions](https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/setup-linux.html#setup-linux-from-source)
and specify the `-DBUILD_ONLY="kms"` flag to `cmake` in the instructions provided.

Now, build and install the AWS Encryption SDK for C:

    git clone --recurse-submodules https://github.com/aws/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -G Xcode -DBUILD_SHARED_LIBS=ON -DOPENSSL_ROOT_DIR="/usr/local/opt/openssl@1.1" ../aws-encryption-sdk-c 
    xcodebuild -target install; cd ..

### Windows Build Recipe

**Note**: See the [docker-images folder](https://github.com/aws/aws-encryption-sdk-c/tree/master/docker-images) for some Windows build recipes that automate many of these steps.

Install Visual Studio version 15 or later with the Windows Universal C Runtime and [Git for Windows](https://git-scm.com/download/win).

Use the "x64 Native Tools Command Prompt" for all commands listed here. Run the following commands in the directory where you want to do the build and installation.

Install Microsoft vcpkg by [following these directions](https://github.com/microsoft/vcpkg#quick-start-windows). Note the path to your `vcpkg.cmake` tool. This path will be something like `vcpkg\scripts\buildsystems\vcpkg.cmake` and you will need to pass it as `-DCMAKE_TOOLCHAIN_FILE` in your builds.

Use vcpkg to install prerequisites:

    vcpkg install curl:x64-windows openssl:x64-windows

You may also want to [configure vcpkg for Visual Studio CMake projects](https://github.com/microsoft/vcpkg#vcpkg-with-visual-studio-cmake-projects).

Build the AWS SDK for C++. This installs the aws-c-common dependency, too. If you need the AWS SDK for C++ only to use the 
AWS Encryption SDK, you have the option to build only the AWS KMS SDK. Add the `-DBUILD_ONLY=kms` to build only the AWS KMS client.

Follow [these instructions](https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/setup-windows.html#setup-windows-from-source), using `-DCMAKE_TOOLCHAIN_FILE` as described in the vcpkg setup instructions. Add `-DBUILD_SHARED_LIBS=ON` for shared libraries or `-DBUILD_SHARED_LIBS=OFF` for static libraries.

Now, build and install the AWS Encryption SDK for C. Be sure to update `-DCMAKE_TOOLCHAIN_FILE` in the commands below. Change `-DBUILD_SHARED_LIBS=ON` to `OFF` if building static libraries.

Update `-DCMAKE_PREFIX_PATH` to the location of your AWS SDK for C++ and aws-c-common installations.

    git clone --recurse-submodules https://github.com/aws/aws-encryption-sdk-c.git
    mkdir build-aws-encryption-sdk-c && cd build-aws-encryption-sdk-c
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_TOOLCHAIN_FILE"=%cd%\..\vcpkg\scripts\buildsystems\vcpkg.cmake" -DCMAKE_PREFIX_PATH="C:/Program Files (x86)/aws-cpp-sdk-all;C:/Program Files (x86)/aws-cpp-sdk-all/lib/aws-c-common" ..\aws-encryption-sdk-c
    cmake --build . && cmake --build . --target install && cd ..

## Building C only, without AWS KMS support

If you don't need AWS KMS support, you can build the AWS Encryption SDK for C without the AWS SDK. This build is C-only with no C++ support
required.

To build without AWS KMS support, follow the build instructions above for your platform, substituting aws-c-common for aws-sdk-cpp.

## Doxygen Documentation

To build the documentation, you'll need [doxygen](http://www.doxygen.nl/) installed.  Check the [downloads](http://www.doxygen.nl/download.html) page 
or use your OS package manager.

Next, rerun the above cmake with a `-DBUILD_DOC="ON"` flag before building aws-encryption-sdk-c.

Finally, run either `make doc_doxygen` (Unix), `MSBuild.exe .\doc_doxygen.vcxproj` (Windows) or `xcodebuild -scheme doc_doxygen` (Mac) to generate the documentation.

## Compiling your program using the AWS Encryption SDK for C

Once you have installed the AWS Encryption SDK for C, you are ready to start writing
your own programs with it.

When doing a C compilation (not using the AWS KMS keyring) be sure to include the flags
``-lcrypto -laws-encryption-sdk -laws-c-common``.

When doing a C++ compilation (using the AWS KMS keyring) be sure to include the flags
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

Note that the C++ files using the AWS KMS keyring will require
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
the C++ components, (enabling use of the AWS KMS keyring.) You can override the detection
logic by setting `-DBUILD_AWS_ENC_SDK_CPP=OFF` to never build the C++ components or
by setting `-DBUILD_AWS_ENC_SDK_CPP=ON` to require building the C++ components (and
fail if the C++ dependencies are not found.)

## License

This library is licensed under the Apache 2.0 License.
