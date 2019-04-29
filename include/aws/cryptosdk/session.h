/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AWS_CRYPTOSDK_SESSION_H
#define AWS_CRYPTOSDK_SESSION_H

#include <aws/cryptosdk/materials.h>

/**
 * @defgroup session Session APIs
 * The session is the primary API that encrypts or decrypts your data.
 * To encrypt or decrypt data, configure your CMM, create a session object,
 * and process your plaintext or ciphertext through this session object.
 *
 * Typically using a session object will proceed through the following phases:
 *
 * 1. Create and configure a session object (or reuse an existing session that you have
 *    reset and configured)
 * 2. Invoke @ref aws_cryptosdk_session_process in a loop that provide all of the input
 *    plaintext or ciphertext, and produces some output data
 * 3. When encrypting, after all input data is consumed,
 *    @ref aws_cryptosdk_session_set_message_size (if it hasn't been called already) to
 *    mark the end of the message.
 * 4. To process or generate trailing data, invoke @ref aws_cryptosdk_session_process in
 *    a loop with no input data until @ref aws_cryptosdk_session_is_done returns true.
 *
 * Most configuration functions will fail if invoked after the first call to @ref aws_cryptosdk_session_process,
 * as the header is generated (thus committing the session to a particular set of parameters)
 * at this time.
 *
 * The session object does not internally buffer your data; if you pass buffers that are too
 * small, it may process only a portion of the supplied data, or none at all. The @ref
 * aws_cryptosdk_session_estimate_buf function can be used to get a more accurate estimate
 * of the amount of buffer space required to make further progress.
 *
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

struct aws_cryptosdk_session;

enum aws_cryptosdk_mode { AWS_CRYPTOSDK_ENCRYPT = 0x9000, AWS_CRYPTOSDK_DECRYPT = 0x9001 };

/**
 * Creates a new encryption or decryption session.
 *
 * @return The new session, or NULL on failure (in which case, an AWS error code is set)
 *
 * @param allocator The allocator to use for the session object and any temporary
 *                  data allocated for the session
 * @param mode The mode (AWS_CRYPTOSDK_ENCRYPT or AWS_CRYPTOSDK_DECRYPT) to start
 *             in. This can be changed later with @ref aws_cryptosdk_session_reset
 * @param keyring The keyring which will encrypt or decrypt data keys for this session.
 *                This function uses a default CMM to link the session and keyring.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_session *aws_cryptosdk_session_new_from_keyring(
    struct aws_allocator *allocator, enum aws_cryptosdk_mode mode, struct aws_cryptosdk_keyring *keyring);
    
/**
 * Creates a new encryption or decryption session.
 *
 * @return The new session, or NULL on failure (in which case, an AWS error code is set)
 *
 * @param allocator The allocator to use for the session object and any temporary
 *                  data allocated for the session
 * @param mode The mode (AWS_CRYPTOSDK_ENCRYPT or AWS_CRYPTOSDK_DECRYPT) to start
 *             in. This can be changed later with @ref aws_cryptosdk_session_reset
 * @param cmm The crypto material manager which will provide key material for this
 *            session.
 */
AWS_CRYPTOSDK_API
struct aws_cryptosdk_session *aws_cryptosdk_session_new_from_cmm(
    struct aws_allocator *allocator, enum aws_cryptosdk_mode mode, struct aws_cryptosdk_cmm *cmm);

/** Destroys a previously allocated session */
AWS_CRYPTOSDK_API
void aws_cryptosdk_session_destroy(struct aws_cryptosdk_session *session);

/**
 * Resets the session, preparing it for a new message. This function can also change
 * a session from encrypt to decrypt, or vice versa. After reset, the currently
 * configured allocator, CMM, and frame size to use for encryption are preserved.
 *
 * @param session The session to reset
 * @param mode The new mode of the session
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_session_reset(struct aws_cryptosdk_session *session, enum aws_cryptosdk_mode mode);

/**
 * Sets the frame size to use for encryption. If zero is specified, the message
 * will be processed in an unframed mode. If this function is not called, a
 * reasonable default will be used.
 *
 * This function will fail if invoked in decrypt mode, or if
 * @ref aws_cryptosdk_session_process has been called.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_session_set_frame_size(struct aws_cryptosdk_session *session, uint32_t frame_size);

/**
 * Sets the precise size of the message to encrypt. This function must be
 * called exactly once during an encrypt operation. You do not need to call it
 * before beginning to pass data, but providing the message size up front may
 * improve efficiency.
 *
 * If the session has already processed more than message_size bytes, or if this
 * method is called more than once, the session will enter an error state.
 *
 * This method is how the end of data is determined. If this is not called,
 * @ref aws_cryptosdk_session_process cannot write the end-of-message
 * frames and instead will continue to expect additional data.
 *
 * Note that if the frame size is set to zero (i.e. this is a one-shot encrypt),
 * a message size must be set before any input data can be processed.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_session_set_message_size(struct aws_cryptosdk_session *session, uint64_t message_size);

/**
 * Provides an upper bound on the message size. This hint is useful when the exact
 * message size is not known up-front, but the configured CMM still needs to make use
 * of message size information. For example, the caching CMM enforces an upper bound
 * on the number of bytes encrypted under a cached key. If this method is not called,
 * it must assume that you are processing an unbounded amount of data, and it will
 * therefore bypass the cache.
 *
 * This method may be called more than once (the smallest call wins). The session will
 * enter an error state if more than the smallest bound of data is written, or if the
 * precise message size passed to aws_cryptosdk_session_set_message_size exceeds the
 * bound.
 *
 * It is recommended that the bound be set before invoking @ref aws_cryptosdk_session_process;
 * failing to do so will result in the CMM being passed an unbounded message size.
 * This is an issue in particular with the caching CMM, which must then assume that
 * your message will exceed size-based usage limits on cached keys.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_session_set_message_bound(struct aws_cryptosdk_session *session, uint64_t max_message_size);

/**
 * Attempts to process some data through the cryptosdk session.
 * This method may do any combination of
 *   1. Consuming some data from the input buffer
 *   2. Producing some data in the output buffer
 *   3. Entering an error state, and raising the error in question.
 *
 * The data referenced by the input and output cursors must not overlap.
 * If this method raises an error, the contents of the output buffer will
 * be zeroed. The buffer referenced by the input buffer will never be modified.
 *
 * If there is insufficient output space and/or insufficient input
 * data, this method may not make any progress. The @ref aws_cryptosdk_session_estimate_buf
 * method may be used to determine how much data may be needed at
 * this stage of processing. Note that these estimates may change once
 * the header has been parsed.
 *
 * Upon return, *out_bytes_written and *in_bytes_read will report the number
 * of bytes consumed from the output and input buffers, respectively.
 *
 * This method will return successfully unless the session has entered
 * an error state. Use @ref aws_cryptosdk_session_is_done to determine if the
 * entire message has been processed.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_session_process(
    struct aws_cryptosdk_session *session,
    uint8_t *outp,
    size_t outlen,
    size_t *out_bytes_written,
    const uint8_t *inp,
    size_t inlen,
    size_t *in_bytes_read);

/**
 * Returns true if the session has finished processing the entire message.
 *
 * Your application should continue calling @ref aws_cryptosdk_session_process until
 * this function returns true; trailing signatures require that some ciphertext
 * data be processed after all plaintext has been consumed or generated.
 */
AWS_CRYPTOSDK_API
bool aws_cryptosdk_session_is_done(const struct aws_cryptosdk_session *session);

/**
 * Returns the algorithm ID in use for this message via *alg_id.
 * Raises AWS_CRYPTOSDK_ERR_BAD_STATE if the algorithm ID has not yet
 * been determined (in this case, the session remains usable and does not
 * enter an error state). Guaranteed to succeed if @ref aws_cryptosdk_session_is_done
 * returns true, but may succeed earlier in the message as well.
 */
AWS_CRYPTOSDK_API
int aws_cryptosdk_session_get_algorithm(const struct aws_cryptosdk_session *session, enum aws_cryptosdk_alg_id *alg_id);

/**
 * Estimates the amount of buffer space needed to make forward progress.
 * Supplying the amount of data indicated here to @ref aws_cryptosdk_session_process
 * guarantees that some kind of progress will be made - although this progress
 * may in some cases only mean that the size estimates are updated with a (larger)
 * more accurate value.
 *
 * This method never fails, but if the session is in an error state or is
 * only partially initialized, the returned sizes may not be meaningful.
 */
AWS_CRYPTOSDK_API
void aws_cryptosdk_session_estimate_buf(
    const struct aws_cryptosdk_session *AWS_RESTRICT session,
    size_t *AWS_RESTRICT outbuf_needed,
    size_t *AWS_RESTRICT inbuf_needed);

/**
 * Returns a read-only pointer to the encryption context held by the session.
 * This will return NULL if it is called too early in the decryption process,
 * before the SDK has finished deserializing and handling the encryption
 * context from the header of the ciphertext.
 *
 * This may be called at any time during or after the encryption process for
 * read-only access to the encryption context, but for setting the encryption
 * context, use aws_cryptosdk_get_enc_ctx_ptr_mut instead.
 *
 * The hash table pointed to by this pointer lives until the session is
 * reset or destroyed. If you want a copy of the encryption context that will
 * outlive the session, you should duplicate it with
 * aws_cryptosdk_enc_ctx_clone and then deallocate the copy with
 * aws_cryptosdk_enc_ctx_clean_up when done with it.
 */
AWS_CRYPTOSDK_API
const struct aws_hash_table *aws_cryptosdk_session_get_enc_ctx_ptr(const struct aws_cryptosdk_session *session);

/**
 * Returns a mutable pointer to the encryption context held by the session.
 * This will only return non-NULL when the session is in encrypt mode AND
 * aws_cryptosdk_session_process has not yet been called.
 *
 * The returned pointer will always point to an already initialized hash
 * table. Callers MUST not clean up or re-initialize the hash table.
 * The encryption context is an aws_hash_table with key and value both
 * using the aws_string type.
 *
 * See the interfaces in hash_table.h and string.h in aws-c-common for
 * guidance on how to add elements to the encryption context.
 *
 * Do not use this pointer across calls to the session. Doing so results
 * in undefined behavior.
 *
 * See documentation of aws_cryptosdk_session_get_enc_ctx_ptr for how to
 * make your own copy of the encryption context, if desired.
 */
AWS_CRYPTOSDK_API
struct aws_hash_table *aws_cryptosdk_session_get_enc_ctx_ptr_mut(struct aws_cryptosdk_session *session);

/**
 * Returns a read-only pointer to the keyring trace held by the session.
 * This will return NULL if called too early in the encryption or
 * decryption process. For best results, call after checking that
 * aws_cryptosdk_session_is_done returns true.
 *
 * When this returns a non-NULL pointer, it will always point to an
 * already initialized aws_array_list with elements of type
 * struct aws_cryptosdk_keyring_trace_record.
 *
 * See keyring_trace.h for more information on the format of the trace.
 *
 * The trace pointed to by this pointer lives until the session is
 * reset or destroyed. If you want a copy of the trace that will
 * outlive the session, you should duplicate it with
 * aws_cryptosdk_keyring_trace_copy_all and then deallocate the
 * copy with aws_cryptosdk_keyring_trace_clean_up when done with it.
 */
AWS_CRYPTOSDK_API
const struct aws_array_list *aws_cryptosdk_session_get_keyring_trace_ptr(const struct aws_cryptosdk_session *session);

#ifdef __cplusplus
}
#endif

/** @} */  // doxygen group session

#endif
