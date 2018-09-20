
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
