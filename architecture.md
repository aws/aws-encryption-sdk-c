## Summary

This RFC lays out the ground rules for the native SDK's general architecture.

## Out of Scope

This RFC does not attempt to specify the exact API of the native SDK. This will
be primarily addressed in code reviews instead.

## Motivation

Having a high-level overview of the native SDK architecture helps us identify
potential issues before getting knee-deep in implementation.

## Drawbacks

Predetermining too much before implementation may result in us finding that
parts of the implementation cannot meet the spec, requiring us to revisit
issues again.

For this reason, this spec is intended to address overall architectural
concepts and design patterns, and not specific APIs.

## Guide-level Explanation

The AWS native encryption SDK is a portable, native-code implementation of the
Encryption SDK, using the standard C99 programming language for maximum
portability. The native encryption SDK is a suitable starting point for
bindings to other languages, or for deployment on constrained platforms.

The native SDK is designed to operate at a lower level, supporting operations
on platforms where threading may not be available, or where memory allocation
is difficult. For this reason, some of the APIs may seem more verbose or
complex than you may be used to in other languages.

### General usage

To perform an encryption operation, you will first construct an object to
represent the cryptographic materials in use. This could be a master key
(`struct aws_cryptosdk_mk`), master key provider (`struct
aws_cryptosdk_mk_provider`), or crypto materials manager (`struct
aws_cryptosdk_cmm`). These objects, once constructed and configured, are
thread-safe and can be used throughout your application.

For each message you wish to encrypt or decrypt, you will then create a `struct
aws_cryptosdk_session`. This represents the state of the in-progress encryption
or decryption operation. You will configure this session with the parameters
needed for the encrypt or decrypt operation. Then, you will pass the plaintext
(for encrypt) or ciphertext (for decrypt) through this session.

The SDK's API allows you to either use a low-level method for passing the data
through the session, or some higher level convenience APIs. The low-level API
takes an input and output buffer, and will attempt to process some data from
the input to the output. Note that it may consume input without producing
output, or vice versa.

In order to make forward progress, the input and output buffers need to be
large enough to hold a single frame (or the message headers). The session API
provides a method which can be used to query how large the buffer should be
(how much input data, and how much space for output data needs to be available)
for the next call.

As a convenience, higher level APIs are provided to encrypt or decrypt a
message in a single call, placing the results into a new heap-allocated buffer.

### Memory ownership

In general, as the caller you are responsible for making sure that whatever you pass
into an encryption SDK 'setter' method remains valid until the object you set it upon
is freed, or until the field in question is set to something different.

For example, if you add an encryption context key and value to an encrypting session,
the memory pointed to by the key and value must remain valid and unchanged until the
session is cleared or destroyed, or that particular context key is overwritten.

### Asynchronicity

Session objects support a mode of operation in which the MK/MKP/CMM initiates
an asynchronous operation to obtain the cryptographic materials for this
operation, then returns immediately. In this case the backing materials
providers SHOULD support integration with your application's event loop, so
that they can signal completion, and cause your application to poll the session
to determine if the materials are ready, and then to make further progress.
However, on extremely constrained systems, simply polling periodically is also an
option.

### Threading rules

Session objects are not thread safe, but (if supported by your MK/MKP/CMMs) are
thread-portable. When using async operations, you must ensure that, including
asynchronous wakeups, sessions are not used from multiple threads at the same
time.

Master keys, master key providers, and crypto material managers are
thread-safe, with the exception of any mutating configuration operations.

### ABI compatibility

By default, the AWS Encryption SDK builds and exposes only functions that are
considered API- and ABI-stable; that is, we expect that both existing code as
well as _existing binaries_ will remain compatible with future versions of the
encryption SDK.

This compatibility is achieved primarily by hiding internal data structures;
these structures must be allocated through helper functions, and cannot be
directly accessed from user code.

For objects that must be extended by external code, we use an extensible vtable
approach. With this approach, an object implementing, say, a master key, must
contain a pointer to a vtable, located at the address of the master key itself.
That is, your master key structure definition and allocation code looks like:

    struct mymasterkey {
        const struct aws_cryptosdk_mk_vt *vtable;
        // internal state
    };

    static const struct aws_cryptosdk_mk_vt mymasterkey_vt = {
        .size = sizeof(mymasterkey_vt),
        .debug_name = "mymasterkey",
        .destroy = mymasterkey_destroy,
        // other method implementations...
    };

    struct aws_cryptosdk_mk *mymasterkey_new(struct aws_platform_t *platform, struct aws_allocator_t *allocator) {
        struct mymasterkey *mk = aws_allocate(allocator, sizeof(*mk));
        if (!mk) {
            return NULL;
        }

        mk->vtable = mymasterkey_vt;
        // ... other setup ...

        return (struct aws_cryptosdk_mk *)mk;
    }

Note that the vtable always contains a field specifying the size of the vtable.
This allows us to define new members of the vtable in the future, as long as we
place them at the end. Code invoking these vtable methods MUST check that the
vtable member they are looking for is not beyond the end of the vtable AND that
the function entry is not NULL. If the entry is beyond the end or NULL, is,
this code MUST either fail the call or invoke a compatibility shim or default
implementation.

To make this easier, wrapper functions will be provided for all vtable calls
which take care of the bounds and NULL checks.

### Static linking (relaxed ABI) mode

***This mode may not be available for the initial release***

The above ABI compatibility design causes some difficulty for constrained systems.
In particular, it requires extensive heap allocation, and introduces additional
function call shims that introduce overhead.

As a compromise to help mitigate these issues, when statically linking the
encryption SDK, it is possible to relax the ABI compatibility model, exposing
structure definitions to your user code. This means that it is possible to
statically (or stack) allocate all working memory needed for the encryption
SDK's operation.

Because this effectively caps the amount of working memory used, this will
subject your application to some limitations. For example, the size of the
header buffers must be set ahead of time; if the header is too large for the
buffer, the encrypt or decrypt operation will fail. Likewise, trailing
signature validation may require preallocating space for temporary results.

### Error reporting

To avoid leaking secrets through side-channels, the encryption SDK reports
relatively coarse error information, primarily through error codes stored in a
thread-local error number field. A successful operation returns `0`; on
failure, a nonzero value is returned, and the error code stashed in
thread-local space. This thread-local error number is shared with other AWS C
SDKs, with our C SDK getting a reserved range of error codes.

When a session operation returns an error, it can be useful to distinguish
between a permanent failure (e.g. corrupt ciphertext) and a temporary failure
(e.g. output buffer too small). Session objects therefore have an operation
which checks for permanent failure, and returns the relevant error code if this
condition is detected.

In some cases it can be useful to extract additional error information from
master keys or CMMs. For example, it is useful to distinguish between a KMS
access denied error vs a bad credentials error vs a network error. This error
reporting is left up to the master keys themselves. I anticipate this will be
part of the AWS SDK for C's core error reporting framework, possibly using a
thread-local error callback.

## Reference-level Explanation

### New concepts

The native encryption SDK introduces the idea of a 'session'. This concept does
not directly exist in other languages, but in some ways is similar to the
public `CryptoInputStream` and `CryptoOutputStream`, or the internal
`MessageCryptoHandler`.

Essentially, the session represents the overall encryption process - including
the initial configuration, to the streaming and internal buffers needed
therein.

Using the session proceeds in a series of steps:

* First, the calling code allocates a new session, passing the platform and allocator
callback structures (or NULL to use a reasonable default).
* The calling code configures the session - setting whether this is in encrypt or decrypt
mode, passing the master key, provider, or CMM, setting frame size (limits), etc.
* The calling code pumps data through the session. Each time it pumps, it passes an input
and output buffer. The session may consume input data and/or produce output data.
* On decrypt, the session will indicate when the header is ready for early inspection.
* Eventually end-of-data is signalled. On decrypt, this is signalled by the session;
on encrypt, the caller signals end-of-plaintext, then the session signals end-of-ciphertext
once the ciphertext is pumped through.
* Finally, the session is either reset or freed.

Some of these steps can be wrapped with helper functions. For example, we can
provide a one-shot operation which handles the data pumping internally.
However, this basic internal architecture is intended to provide sufficient
flexibility for streaming use cases as the underlying primitive API.

### Memory ownership

Master keys, master key providers, and CMMs are not owned by the session. They may be
used in multiple sessions simultaneously. Calling code is responsible for freeing them
when appropriate (but not while they are in use).

The session owns the header that it constructs. In particular, on decrypt, it owns all
context key and value buffers, and will free them when the session is reset or destroyed.

TODO: should we allow context key/values to be owned by the caller on encrypt?

It is the caller's responsibility to maintain input and output buffers of
sufficient size.  The session provides a call which will inform the caller of
the input/output buffer size required (this is based on the size of the
encryption frames and/or header). If the input/output buffers are too small,
pump will return an error, and the caller must call it again after resizing its
buffers appropriately.

Note that this means that the session's internal heap memory usage is limited
to cipher state and the header itself.

### Async execution

Optionally, interactions with the CMM or master key (provider) can be asynchronous.

Asynchronous operations are useful when executing code in the context of an
event loop; if we need to wait for a network operation, we would like to pop
back up to the event loop. This is particularly important in the AWS C SDK
architecture, which is entirely based on asynchronous code running in event
loops.

Because this architecture introduces substantial complexity, we would like for
asynchronicity to be optional. In particular, for non-networked MKs, it doesn't
make sense to use asynchronicity at all. However, for reasons that will be addressed
below, this requires support from the MK(P)/CMM to be truly optional, and so we can
only state it as a recommendation (CMMs/MK/MKPs SHOULD support synchronous operation).

Async operation is based on a polled-futures approach. When invoking an asynchronous API,
we pass in a pointer to an async state buffer:

    void do_something(..., struct aws_async *async);

    struct aws_async {
        ///// Filled by caller:
        size_t st_size; // structure size
        void *loop_info; // pointer to event loop
        void (*wakeup)(struct aws_async *async); // should be invoked when poll needs to be called

        ///// Filled by async operation
        void *caller_state; // arbitrary state handle
        // Cancel the current operation. After invocation, neither cancel
        // nor poll may be called, and the aws_async structure may be destroyed
        void (*cancel)(struct aws_async *async);
        // Poll for results. Returns AWS_ERR_PENDING if the operation is not complete.
        // Otherwise, returns a result code and may put a result in *result.
        int (*poll)(struct aws_async *async, void *result);
    };

First, if `do_something` can complete synchronously, it does so. Otherwise, it sets up the
callbacks in the `async` structure, and returns `AWS_ERR_PENDING`. It also uses `loop_info`
to arrange for `wakeup` to be called on the current event loop when `poll` needs to be invoked.

The exact way in which `loop_info` is used is unspecified; this is up to the I/O library
in use and is beyond the scope of the encryption SDK. However we do set the following rules:

* `poll` may be invoked at arbitrarily many times, until either `poll` returns something other than
`AWS_ERR_PENDING` or `cancel` is invoked.
* It is the responsibility of the calling code and the async operation, in concert with `loop_info`
to ensure that `wakeup` is not invoked at the same time as any other `wakeup` on the same session,
or any other top-level session call on the same session.
* It is the responsibility of code invoking the async operation to ensure that
parallel or recursive calls to `poll` or `cancel` are not performed.
* Once `wakeup` is invoked, the caller of the async operation will arrange for
`poll` to be invoked at some point in the future. It is possible that `wakeup` might be invoked
before that `poll`, in which case we do not guarantee that the number of `poll` will exceed the
number of `wakeup` calls (but rather that the last call will be `poll` or `cancel`, not `wakeup`).
* `wakeup` SHALL NOT be invoked, or be in the process of being invoked, after `cancel` returns, or
after `poll` returns a result other than `AWS_ERR_PENDING`
* `cancel` and `poll` SHALL NOT be invoked after either `cancel` is invoked, or after `poll` returns
a result other than `AWS_ERR_PENDING`.

When poll returns a result, it SHALL be returned via the `result` parameter
passed in, not via any out-pointer argument passed to the original
`do_something`. However, it may rely on any input parameters remaining valid (up until cancel
is called or poll indicates the operation is complete).

At the top level of the session, we then require the caller to opt-in to async operations:

    int aws_cryptosdk_session_set_async(struct aws_cryptosdk_session *session,
      void *loop_info, void *callback_info,
      void (*wakeup)(void *callback_info)
    );

Note that we don't need a full `aws_async` structure as we can cancel by
destroying the session, or poll by pumping data.

When async operation is not being used, we simply pass a NULL `aws_async`
structure. The callee then SHOULD perform the operation synchronously (or
fail). We can't emulate synchronicity internally, because we'd have to come up
with an event loop that the callee understands, and we don't necessarily know
what form that event loop takes.

### Constrained platforms

On some platforms threading may be unavailable, and/or memory allocation may be
constrained. Because most of the core data structures in the encryption SDK are
variable-sized, it's somewhat difficult to fully address that, but we can at
least try.

First, though, we must address the tension between the desire for abi
forwards-compatibility and the desire for memory efficiency. in order to allow
for forwards compatibility, we would like to have the flexibility to expand the
size of internal datastructures in future releases. To do this, we use some
combination of these techniques:

* Forward-declaration of structs (e.g. `struct aws_cryptosdk_session;`), with
the structure definition not being exported

* Methods which allocate structs on the heap with an appropriate size for the
actual implementation of the SDK in use (e.g. `aws_cryptosdk_session_create`)

* For structs which must be caller-allocated, we can add a size field to detect
when fields added later are missing. We must then tolerate not having those
fields available (this is useful for e.g. vtables where a default
implementation for later-added methods can be provided).

The heap allocation requirement, in particular, is difficult for embedded
systems. Embedded systems often avoid heap allocation (sometimes not having a
heap allocator at all). In part this is for efficiency reasons, but the bigger
concern is determinism - it's very hard to accurately predict the impact of
heap fragmentation on memory usage, and for a critical embedded system running
out of memory due to fragmentation could be a serious issue. These systems
therefore often prefer static or stack allocation instead.

In theory, stack allocation can be performed using `alloca` to allocate stack
buffers of unpredictable size. This however is still non-deterministic in that
it could result in a stack overflow if the size requested exceeds the stack size,
and on systems without a MMU this can go undetected at the point of overflow.

To help address these, I propose offering an alternate build option for the
encryption SDK in which only static linking is allowed, and certain internal
datastructures become stack or static-allocatable.

#### Static linking mode

When static linking mode is enabled, we make the following changes to the build system:

* Building a shared library is disabled
* All symbols are marked private - that is, if the static encryption sdk is embedded within
a shared library, no symbols from the encryption SDK itself will be exported
* Additional private headers are included, providing access to the definitions of internal
structs as well as some non-exported helper functions.
* (Optionally) We MAY expose some trivial functions that would otherwise be external symbols as
`static inline` functions to reduce function call overhead.

Note that this option risks breaking both API and ABI forward compatibility.
Users of this mode SHOULD avoid accessing the actual members of these
structures directly. Exposing `static inline` helpers is a better way to
provide access to structure state without breaking API compatibility.

Once we are in this mode, it is possible to statically allocate most things
which are needed for the encryption SDK. For example, you might do something
like:

    static aws_cryptosdk_static_mk_aes myAESkey;
    static char headerbuf[256];
    static aws_cryptosdk_static_session mySession;

    // ...
    aws_cryptosdk_static_mk_aes_init(&myAESkey, raw_key_buf, 16);
    struct aws_cryptosdk_session *session = aws_cryptosdk_static_session_init(&mySession, headerbuf, sizeof(headerbuf));
    // ...

Note that we define a separate static session type. This allows us to include
additional state which would otherwise be heap-allocated, such as the state for
internal cipher objects. The `aws_cryptosdk_static_session` struct might look a bit like:

    struct aws_cryptosdk_static_session {
        struct aws_cryptosdk_session session;
        struct aws_cryptocore_symm_state cipher_state;
        struct aws_cryptocore_md_state signature_state;
        // ...
    };

We SHOULD document which methods do not result in dynamic allocation (assuming
the session was statically constructed), and possibly have an additional
compile option which disables dynamically-allocating methods.

## Rational and Alternatives

### No internal buffering

The API for pumping the session performs no session-internal buffering of
plaintext or ciphertext, except for the header itself. This gives full control
of the bulk side of memory allocation to the application. In particular, it
allows applications to mitigate memory exhaustion issues related to large frame
sizes, if they so choose, and lets them do advanced techniques like reusing
buffers, or mmapping the input or output.

It also allows constrained systems to use statically or stack allocated buffers
for the bulk buffering. However, there is a downside - because the buffer must
be large enough to hold a full frame, using small stack buffers (e.g. `char
inbuf[1024]`) will not be sufficient for typical frame sizes.

An alternate approach would be to internally allocate buffers, and copy partial
frames into these buffers. This causes more overhead due to memory copies, but
simplifies the coding model. Ultimately, however, this can be implemented on
top of the existing API as a helper function (perhaps with a couple of helper
pointers in the session object to stash the allocated buffers), and so is not
required as the fundamental low-level API.

### Static linking compromise

As discussed above, when dynamic linking we choose to have a stable ABI, but
have introduced a relaxed-ABI static linking mode as a compromise. There are
other compromises we could have made instead, however, such as:

* Only ABI-compatible builds allowed (this may be the initial release as we
figure out how much to expose in relaxed-ABI mode)

* Only static linking allowed

* No ABI compatibility guarantees, even when linking as a shared library

* ABI compatibility is provided but we expect to perform major version/soname
revisions frequently.

The latter three, however, are prone to issues. Specifically, they can cause
problems when multiple shared libraries depend on _different versions_ of the
encryption SDK in the same application. The last option additionally requires
considerable judgement on the part of the maintainer to determine when a
version bump is required.

## Unresolved Questions

### What parts of the design do you expect to resolve through the RFC process before this gets merged?

Is it worth building in the static linking mode? Is that mode sufficient? Note that static allocation will require us to add static allocation support to the underlying crypto primitives.

Does eschewing buffering in the core session APIs make things easier or harder?

### What parts of the design do you expect to resolve through implementation prior to finalization?

Specific APIs and naming concerns are deferred to code reveiews.
