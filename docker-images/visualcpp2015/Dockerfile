# escape=`

FROM microsoft/windowsservercore

ADD https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe /vc_redist.x64.exe
RUN start /wait C:\vc_redist.x64.exe /quiet /norestart

# Install chocolatey
RUN @powershell -NoProfile -ExecutionPolicy unrestricted -Command "(iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))) >$null 2>&1"

RUN choco install git 7zip -y
RUN choco install cmake --installargs 'ADD_CMAKE_TO_PATH=""System""' -y

# Install Visual C++ Build Tools, as per: https://chocolatey.org/packages/visualcpp-build-tools
RUN choco install visualcpp-build-tools -version 14.0.25420.1 -y

# Add msbuild to PATH
RUN setx /M PATH "%PATH%;C:\Program Files (x86)\MSBuild\14.0\bin"

# Test msbuild can be accessed without path
RUN msbuild -version

ADD cleanup-vcpkg.ps1 /cleanup-vcpkg.ps1

# Set up vcpkg and install dependencies
RUN git clone https://github.com/Microsoft/vcpkg.git c:\vcpkg
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

