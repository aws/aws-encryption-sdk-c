#!/bin/sh -x

###
# cppcheck 1.82 (the latest available on the ubuntu image we use)
# has a bug where it reports an error exit code even when there are
# no warnings. Download and install 1.84 instead.
#
# TODO: When we have the infrastructure set up for custom docker images,
# build cppcheck into the image

codebuild-build-dependency https://github.com/danmar/cppcheck.git --git-tag 1.84 -DUSE_CLANG=ON
PATH=/deps/cppcheck/install/bin:$PATH

cppcheck --version

cppcheck                                                    \
-j 1                                                        \
--enable=all --std=c99 --language=c                         \
--template='[{file}:{line}]: ({severity},{id}){message}'    \
--force --error-exitcode=42                                 \
-v                                                          \
                                                            \
-I include                                                  \
-i .cbmc-batch                                              \
                                                            \
--suppress=unusedFunction                                   \
--suppress=missingInclude                                   \
--suppress=purgedConfiguration                              \
--suppress=allocaCalled:tests/unit/t_cipher.c               \
--suppress=allocaCalled:tests/unit/t_header.c               \
--suppress=memleak:tests/decrypt.c                          \
                                                            \
-q .

exit $?
