/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <utils.h>

bool aws_byte_buf_contents_match(const struct aws_byte_buf *const lhs, const struct aws_byte_buf *const rhs) {
    /* Filter null pointers */
    if (!lhs || !rhs) return (lhs == rhs); /* Return true if both null */
    if (lhs->len != rhs->len) return false;
    if (lhs->len > 0) {
        for (size_t i = 0; i < lhs->len; ++i) {
            if (lhs->buffer[i] != rhs->buffer[i]) return false;
        }
    }
    return true;
}

bool key_contents_match(const struct content_key *ckey, const struct data_key *dkey, const size_t max_len) {
    /* Filter null pointers */
    if (!ckey || !dkey) return (ckey == dkey); /* Return true if both null */
    if (!ckey->keybuf || !dkey->keybuf) return (ckey->keybuf == dkey->keybuf);
    for (size_t i = 0; i < max_len; ++i) {
        if (ckey->keybuf[i] != dkey->keybuf[i]) return false;
    }
    return true;
}
