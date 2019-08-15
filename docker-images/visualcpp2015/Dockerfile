# escape=`
# Keep parity with the upstream tags at https://hub.docker.com/_/microsoft-windows-servercore
FROM aws_encryption/windows_base:1607-KB4512517

LABEL Description="Build Testing image for VS2015"
LABEL Vendor="AWS"
LABEL Version="1.0"

# Install Visual C++ Build Tools, as per: https://chocolatey.org/packages/visualcpp-build-tools
RUN choco install visualcpp-build-tools -version 14.0.25420.1 -y

# Add msbuild to PATH
RUN setx /M PATH "%PATH%;C:\Program Files (x86)\MSBuild\14.0\bin"

# Test msbuild can be accessed without path
RUN msbuild -version

CMD [ "cmd.exe" ]
