# escape=`
# Keep parity with the upstream tags at https://hub.docker.com/_/microsoft-windows-servercore
FROM aws_encryption/windows_base:1607-KB4512517

LABEL Description="Build Testing image for VS2017"
LABEL Vendor="AWS"
LABEL Version="1.0"

# Install Visual C++ Build Tools, as per: https://chocolatey.org/packages/visualcpp-build-tools
RUN powershell -NoProfile -InputFormat None -Command `
    choco install visualcpp-build-tools -version 15.0.26228.20170424 -y; `
    Write-Host 'Waiting for Visual C++ Build Tools to finish'; `
    Wait-Process -Name vs_installer

# Add msbuild to PATH
RUN setx /M PATH "%PATH%;C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\MSBuild\15.0\Bin"

# Test msbuild can be accessed without path
RUN msbuild -version

CMD [ "cmd.exe" ]
