#!/bin/bash

find {.,aws-encryption-sdk-cpp}/{include,source,tests} -name '*.h' -or -name '*.c' -or -name '*.cpp' | xargs clang-format -i
