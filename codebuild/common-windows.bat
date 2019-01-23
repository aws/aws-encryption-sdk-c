REM Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
REM
REM Licensed under the Apache License, Version 2.0 (the "License"). You may not use
REM this file except in compliance with the License. A copy of the License is
REM located at
REM
REM http://aws.amazon.com/apache2.0/
REM
REM or in the "license" file accompanying this file. This file is distributed on an
REM "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
REM implied. See the License for the specific language governing permissions and
REM limitations under the License.

rmdir/s/q deps
mkdir deps
cd deps
git clone -b 1.7.36 https://github.com/aws/aws-sdk-cpp.git || goto error
mkdir build-aws-sdk-cpp
cd build-aws-sdk-cpp
cmake %* -DCMAKE_INSTALL_PREFIX=c:/deps -DCMAKE_BUILD_TYPE="Release" -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DBUILD_ONLY="kms" -DENABLE_UNITY_BUILD=ON ../aws-sdk-cpp || goto error
msbuild.exe ALL_BUILD.vcxproj /p:Configuration=Release || goto error
msbuild.exe INSTALL.vcxproj /p:Configuration=Release || goto error

cd ..\..

rmdir/s/q build
mkdir build
cd build
cmake %* -DCMAKE_INSTALL_PREFIX=c:/deps -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE="Release" -DBUILD_AWS_ENC_SDK_CPP=ON -DAWS_ENC_SDK_END_TO_END_TESTS=ON ../ || goto error
msbuild.exe ALL_BUILD.vcxproj /p:Configuration=Release || goto error
ctest -V --output-on-failure -j4 || goto error

goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%

