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

mkdir deps
cd deps
git clone https://github.com/awslabs/aws-c-common.git || goto error
mkdir c-common-build
cd c-common-build
cmake %* -DCMAKE_INSTALL_PREFIX=c:/deps -DCMAKE_BUILD_TYPE="Release" -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake ../aws-c-common || goto error
msbuild.exe aws-c-common.vcxproj /p:Configuration=Release || goto error
msbuild.exe INSTALL.vcxproj /p:Configuration=Release || goto error


cd ..\..

mkdir build
cd build
cmake %* -DCMAKE_INSTALL_PREFIX=c:/deps -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE="Release" -DFORCE_KMS_KEYRING_BUILD=ON -DAWS_ENC_SDK_END_TO_END_TESTS=ON ../ || goto error
msbuild.exe ALL_BUILD.vcxproj /p:Configuration=Release || goto error
ctest -V --output-on-failure -j4 || goto error

goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
