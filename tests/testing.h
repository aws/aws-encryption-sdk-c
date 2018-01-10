#ifndef TESTING_H
#define TESTING_H

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

#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) {\
            printf("\nTest failed: %s is false at %s:%d\n", #cond, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#endif
