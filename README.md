## AWS Encryption SDK C

The AWS Encryption SDK for C provides easy-to-use envelope encryption in C,
with a dataformat compatible with the [AWS Encryption SDKs for Java and
Python](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

**This library is currently under public preview**. Feel free to check out the
code and give it a spin, but be aware that the APIs might change as we get
closer to release. We'd love to hear your feedback on the APIs before they're
fully nailed down.

## Building

You'll first need to build the
[aws-c-common](https://github.com/awslabs/aws-c-common) and (optionally)
[aws-sdk-cpp](https://github.com/aws/aws-sdk-cpp) packages. You'll also need to
build and install openssl 1.0.2 or higher.

Once you've built them, you have two ways of providing their paths to this
package. First, you can `make install` the dependencies to some directory (you
can set `CMAKE_INSTALL_PREFIX` to install to an arbitrary directory), then
configure aws-encryption-sdk-c like so:

    cmake -DCMAKE_PREFIX_PATH=[path to where aws-c-common and aws-sdk-cpp were installed] \
          -DOPENSSL_ROOT_DIR=[path to where openssl was installed] \
          [path to aws-encryption-sdk-c source]

If these dependencies were installed in the default location for library
installations on your system, cmake may be able to find them without these
defines.

You can also point cmake to the `aws-c-common` build directory if you prefer
not to install it, with:

    -Daws-c-common_DIR=[path to the aws-c-common build directory]

Currently, this mode of operation is not supported for the AWS C++ SDK; you
must install that, but you can install it to an alternate installation
directory referenced by `CMAKE_PREFIX_PATH` if you prefer.

### Tips and tricks

When building aws-sdk-cpp, you can save time by only building the subcomponents we need:

    cmake -DBUILD_ONLY="kms" [path to aws-sdk-cpp source]

To enable debug symbols, set `-DCMAKE_BUILD_TYPE=Debug` at initial cmake time,
or use `ccmake .` to update the configuration after the fact.

## License

This library is licensed under the Apache 2.0 License. 
