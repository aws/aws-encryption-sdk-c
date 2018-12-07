This subdirectory contains an implementation of a KMS keyring based on the AWS
SDK for C++.

At the current time, we do not have a full API conforming to C++ conventions (e.g.
we don't have APIs that use `std::shared_ptr`s or similar for resource management);
even when using this keyring, you'll be using the C API for the actual data processing.
This is intended mostly as a stopgap KMS integation until we have a pure-C KMS client
to use instead. It is likely that the API will change at some point in the future when
such a pure-C KMS client becomes available.
