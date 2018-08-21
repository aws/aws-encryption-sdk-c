# escape=`

FROM microsoft/windowsservercore

ADD https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe /vc_redist.x64.exe
RUN start /wait C:\vc_redist.x64.exe /quiet /norestart

# Install chocolatey
RUN @powershell -NoProfile -ExecutionPolicy unrestricted -Command "(iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))) >$null 2>&1"

RUN choco install git 7zip -y
RUN choco install cmake --installargs 'ADD_CMAKE_TO_PATH=""System""' -y

# Install Visual C++ Build Tools, as per: https://chocolatey.org/packages/visualcpp-build-tools
RUN powershell -NoProfile -InputFormat None -Command `
    choco install visualcpp-build-tools -version 15.0.26228.20170424 -y; `
    Write-Host 'Waiting for Visual C++ Build Tools to finish'; `
    Wait-Process -Name vs_installer

# Add msbuild to PATH
RUN setx /M PATH "%PATH%;C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\MSBuild\15.0\Bin"

# Test msbuild can be accessed without path
RUN msbuild -version

ADD cleanup-vcpkg.ps1 /cleanup-vcpkg.ps1

# Set up vcpkg and install dependencies
RUN git clone https://github.com/Microsoft/vcpkg.git c:\vcpkg
RUN powershell -NoProfile -InputFormat None -Command `
    cd  c:\vcpkg; `
    .\bootstrap-vcpkg.bat; `
    .\vcpkg integrate install; `
    c:\cleanup-vcpkg.ps1

RUN powershell -NoProfile -InputFormat None -Command `
    cd c:\vcpkg; `
    .\vcpkg update

RUN powershell -NoProfile -InputFormat None -Command `
    cd c:\vcpkg; `
    .\vcpkg install curl:x86-windows openssl:x86-windows curl:x64-windows openssl:x64-windows; `
    c:\cleanup-vcpkg.ps1

RUN powershell -NoProfile -InputFormat None -Command `
    cd c:\vcpkg; `
    .\vcpkg install aws-sdk-cpp[kms]:x86-windows; `
    c:\cleanup-vcpkg.ps1

RUN powershell -NoProfile -InputFormat None -Command `
    cd c:\vcpkg; `
    try { `
    .\vcpkg install aws-sdk-cpp[kms]:x64-windows; `
    c:\cleanup-vcpkg.ps1 `
    } catch { `
    get-content c:\vcpkg\buildtrees\aws-sdk-cpp\config-x64-windows-out.log `
    }

CMD [ "cmd.exe" ]

