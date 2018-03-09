#include <aws/cryptosdk/buffer.h>
#include "testing.h"

int test_skip() {
    struct aws_cryptosdk_buffer buf;
    char arr[16];

    buf.ptr = arr;
    buf.len = sizeof(arr);

    TEST_ASSERT_INT_EQ(AWS_ERROR_SUCCESS, aws_cryptosdk_buffer_skip(&buf, 10));
    TEST_ASSERT_INT_EQ(AWS_ERROR_SUCCESS, aws_cryptosdk_buffer_skip(&buf, 4));
    TEST_ASSERT_INT_EQ(AWS_ERROR_SHORT_BUFFER, aws_cryptosdk_buffer_skip(&buf, 3));
    TEST_ASSERT_INT_EQ(AWS_ERROR_SUCCESS, aws_cryptosdk_buffer_skip(&buf, 2));
    TEST_ASSERT_INT_EQ(AWS_ERROR_SHORT_BUFFER, aws_cryptosdk_buffer_skip(&buf, 1));

    TEST_ASSERT_INT_EQ(0, buf.len);

    // Check for overflow detection
    buf.ptr = arr;
    buf.len = sizeof(arr);
    TEST_ASSERT_INT_EQ(AWS_ERROR_SHORT_BUFFER, aws_cryptosdk_buffer_skip(&buf, SIZE_MAX));

    buf.len = 0;
    TEST_ASSERT_INT_EQ(AWS_ERROR_SHORT_BUFFER, aws_cryptosdk_buffer_skip(&buf, SIZE_MAX));
    TEST_ASSERT_INT_EQ(AWS_ERROR_SUCCESS, aws_cryptosdk_buffer_skip(&buf, 0));

    return 0;
}


struct test_case buffer_test_cases[] = {
    { "buffer", "test_skip", test_skip },
    { NULL }
};
