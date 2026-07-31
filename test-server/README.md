# ESDK TestServer — C Language_Server

A hand-rolled [rpcv2Cbor](https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html)
HTTP server that implements the ESDK TestServer Smithy contract and delegates
each operation to the AWS Encryption SDK for C built from this repository's
head. No new external dependencies: the HTTP transport (POSIX sockets) and the
CBOR codec are implemented in `test-server/` itself.

The wire contract — the Smithy model, the generated Test_Client, and the Tests
suite — lives in [`aws/aws-crypto-tools-commons`](https://github.com/aws/aws-crypto-tools-commons)
under `esdk/test-server/`. This directory hosts only the C Language_Server.

## What it speaks

- `POST /service/ESDKTestServer/operation/{Operation}`
- Headers `smithy-protocol: rpc-v2-cbor`, `Content-Type: application/cbor`
- CBOR map request/response bodies; errors as a CBOR map `{__type, message}`
- Operations: `CreateClient`, `Encrypt`, `Decrypt`, `EncryptStream`,
  `DecryptStream`. The stream variants drive the session's streaming API
  (`aws_cryptosdk_session_process` in bounded chunks); the blob variants use
  `aws_cryptosdk_session_process_full`.

## Feature support

Wired keyrings/CMMs (see `commons-configuration.json`): Raw AES, Raw RSA
(PKCS1 / OAEP-SHA1 / OAEP-SHA256 — the C library has no OAEP-SHA384/512
padding), multi-keyring, and the caching CMM over any of those.

The AWS KMS keyrings live in this repository's `aws-encryption-sdk-cpp/`
component and need the AWS SDK for C++ at build time; they are not wired into
this server yet, so every `AwsKms*` keyring config returns a modeled
`GenericServerError` and the `aws-kms*` Features are declared unsupported.

## Building and running

Built only with `-DBUILD_TEST_SERVER=ON` (default OFF; POSIX-only). Requires
the same dependencies as the library itself (aws-c-common, OpenSSL).

```bash
make build-server                # cmake configure + build (.build/)
make run-server PORT=8096        # foreground
# or, orchestrated:
make start-server PORT=8096
make wait-for-server PORT=8096
make stop-server PORT=8096
make test                        # server unit + protocol tests, no AWS access
```

If aws-c-common is installed somewhere non-standard, pass
`CMAKE_PREFIX_PATH=/path/to/deps` on the make command line.

## Cross-language run

`make test-server` clones commons at the branch in `commons-configuration.json`
and delegates to its orchestrator, which builds and launches every configured
Language_Server (this one on port 8096, `context=language:c`) and runs the Java
Tests matrix. Needs AWS credentials and a JDK 21+.

## Layout

`cbor.{h,cpp}` (codec), `http.{h,cpp}` (transport), `bridge.{h,cpp}`
(config → keyring/CMM/session translation + clientId registry),
`server.{h,cpp}` (rpcv2Cbor dispatch), `main.cpp`, `tests/`.
