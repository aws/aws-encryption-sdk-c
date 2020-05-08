# escape=`
# Keep parity with the upstream tags at https://hub.docker.com/_/microsoft-windows-servercore
FROM aws_encryption/windows_base:ltsc2016

LABEL Description="Build Testing image for VS2015"
LABEL Vendor="AWS"
LABEL Version="1.0"

# Install Visual C++ Build Tools, as per: https://chocolatey.org/packages/visualcpp-build-tools
RUN choco install visualcpp-build-tools -version 14.0.25420.1 -y

# Add msbuild to PATH
RUN setx /M PATH "%PATH%;C:\Program Files (x86)\MSBuild\14.0\bin"

# Test msbuild can be accessed without path
RUN msbuild -version

RUN powershell -NoProfile -InputFormat None -Command `
    cd c:\vcpkg; `
    .\bootstrap-vcpkg.bat; `
    .\vcpkg update; `
    .\vcpkg integrate install; `
    c:\cleanup-vcpkg.ps1

RUN powershell -NoProfile -InputFormat None -Command `
    cd c:\vcpkg; `
    .\vcpkg install curl:x86-windows openssl:x86-windows curl:x64-windows openssl:x64-windows; `
    c:\cleanup-vcpkg.ps1


CMD [ "cmd.exe" ]
