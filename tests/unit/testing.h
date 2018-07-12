#ifndef AWS_CRYPTOSDK_TESTS_TESTING_H
#define AWS_CRYPTOSDK_TESTS_TESTING_H

#include <stdio.h>

/* Test case groups consist of an array of struct test_case.
 * Each entry represents a single test case, except for the final all-NULL entry which terminates the list.
 */
struct test_case {
    // Test group
    const char *group;
    // Test case name
    const char *name;
    // Test callback - returns 0 for success
    int (*test_fn)();
    // The following members are state that is written by the test runner in its private copy of the entry

    // 1 if the test is enabled and should run
    int enabled;
    // The return value from test_fn
    int result;
};

extern struct test_case header_test_cases[];
extern struct test_case cipher_test_cases[];
extern struct test_case materials_test_cases[];
extern struct test_case enc_context_test_cases[];
extern struct test_case encrypt_test_cases[];
extern struct test_case raw_aes_mk_provider_info_test_cases[];
extern struct test_case raw_aes_mk_decrypt_test_cases[];

#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) {\
            fprintf(stderr, "\nTest failed: %s is false at %s:%d\n", #cond, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_SUCCESS(cond) \
    do { \
        if (cond) { \
            int t_errcode = aws_last_error(); \
            fprintf(stderr, "\nTest failed: Unexpected failure of %s at %s:%d: %s (%d)\n", \
                #cond, __FILE__, __LINE__, aws_error_debug_str(t_errcode), t_errcode); \
                return 1; \
        } \
    } while (0)

#define TEST_ASSERT_INT_EQ(x, y) \
    do { \
        unsigned long long t_x = (x); \
        unsigned long long t_y = (y); \
        if (t_x != t_y) { \
            fprintf(stderr, "Failed: %s (%llu) != %s (%llu) at %s:%d\n", \
                    #x, t_x, #y, t_y, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_INT_NE(x, y) \
    do { \
        unsigned long long t_x = (x); \
        unsigned long long t_y = (y); \
        if (t_x == t_y) { \
            fprintf(stderr, "Failed: %s (%llu) == %s (%llu) at %s:%d\n", \
                    #x, t_x, #y, t_y, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_ADDR_EQ(x, y) \
    do { \
        const void * t_x = (x); \
        const void * t_y = (y); \
        if (t_x != t_y) { \
            fprintf(stderr, "Failed: %s (%p) != %s (%p) at %s:%d\n", \
                    #x, t_x, #y, t_y, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_ADDR_NULL(x) \
    do { \
        const void * t_x = (x); \
        if (t_x) { \
            fprintf(stderr, "Failed: %s != NULL at %s:%d\n", \
                    #x, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_ADDR_NOT_NULL(x) \
    do { \
        const void * t_x = (x); \
        if (!t_x) { \
            fprintf(stderr, "Failed: %s == NULL at %s:%d\n", \
                    #x, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_BUF_EQ(buf, ...) \
    do { \
        static uint8_t expected_arr[] = { __VA_ARGS__ }; \
        struct aws_byte_buf actual_buf = (buf); \
        TEST_ASSERT_INT_EQ(actual_buf.len, sizeof(expected_arr)); \
        if (memcmp(expected_arr, actual_buf.buffer, actual_buf.len)) { \
            fprintf(stderr, "Buffer mismatch at %s:%d (%s)\n  Actual: ", __FILE__, __LINE__, #buf); \
            for (size_t assert_idx = 0; assert_idx < actual_buf.len; assert_idx++) { \
                fprintf(stderr, "%02x ", ((uint8_t *)actual_buf.buffer)[assert_idx]); \
            } \
            fprintf(stderr, "\nExpected: "); \
            for (size_t assert_idx = 0; assert_idx < actual_buf.len; assert_idx++) { \
                fprintf(stderr, "%02x ", expected_arr[assert_idx]); \
            } \
            fprintf(stderr, "\n"); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_CUR_EQ(cur, ...) \
    do { \
        static uint8_t expected_arr[] = { __VA_ARGS__ }; \
        struct aws_byte_cursor actual_cur = (cur); \
        TEST_ASSERT_INT_EQ(actual_cur.len, sizeof(expected_arr)); \
        if (memcmp(expected_arr, actual_cur.ptr, actual_cur.len)) { \
            fprintf(stderr, "Cursor mismatch at %s:%d (%s)\n  Actual: ", __FILE__, __LINE__, #cur); \
            for (size_t assert_idx = 0; assert_idx < actual_cur.len; assert_idx++) { \
                fprintf(stderr, "%02x ", ((uint8_t *)actual_cur.ptr)[assert_idx]); \
            } \
            fprintf(stderr, "\nExpected: "); \
            for (size_t assert_idx = 0; assert_idx < actual_cur.len; assert_idx++) { \
                fprintf(stderr, "%02x ", expected_arr[assert_idx]); \
            } \
            fprintf(stderr, "\n"); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_ERROR(code, expression) \
    do { \
        aws_reset_error(); \
        int assert_rv = (expression); \
        int assert_err = aws_last_error(); \
        int assert_err_expect = (code); \
        if (assert_rv != AWS_OP_ERR) { \
            fprintf(stderr, "Expected error at %s:%d but no error occured; rv=%d, aws_last_error=%04x (expected %04x:%s)\n", \
                    __FILE__, __LINE__, assert_rv, assert_err, assert_err_expect, #code); \
            return 1; \
        } \
        if (assert_err != assert_err_expect) { \
            fprintf(stderr, "Incorrect error code at %s:%d; aws_last_error=%04x (expected %04x:%s)\n", \
                    __FILE__, __LINE__, assert_err, assert_err_expect, #code); \
            return 1; \
        } \
    } while(0)

#endif // AWS_CRYPTOSDK_TESTS_TESTING_H
