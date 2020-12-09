#include <utils.h>

void assert_byte_buf_contents_are_equal(
    const struct aws_byte_buf *const lhs,
    const struct aws_byte_buf *const rhs) {
    assert(lhs && rhs);
    assert(lhs->len == rhs->len);
    if (lhs->len > 0) {
        size_t index;
        __CPROVER_assume(index < lhs->len);
        assert(lhs->buffer[index] == rhs->buffer[index]);
    }
}

void assert_keys_are_equal(
    const struct content_key *ckey,
    const struct data_key *dkey,
    const size_t max_len) {
    assert(ckey && dkey);
    assert(ckey->keybuf && dkey->keybuf);
    size_t index;
    __CPROVER_assume(index < max_len);
    assert(ckey->keybuf[index] == dkey->keybuf[index]);
}