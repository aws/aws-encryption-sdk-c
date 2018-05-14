#include <aws/cryptosdk/materials.h>
#include "testing.h"

int there_is_a_test() {
    // trivial test just to make sure header can be included
    return 0;
}

struct test_case materials_test_cases[] = {
    { "materials", "there is a test", there_is_a_test },
    { NULL }
};
