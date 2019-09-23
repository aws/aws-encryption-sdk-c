# escape=`
# latest is not a tag used by Microsoft see https://hub.docker.com/_/microsoft-windows-servercore
# Note CodeBuilds last error indicated they are using 10.0.14393 build hosts.
FROM mcr.microsoft.com/windows/servercore:1607-KB4512517

LABEL Description="Base image for Build Testing"
LABEL Vendor="AWS"
LABEL Version="1.0"

ADD https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe /vc_redist.x64.exe
RUN start /wait C:\vc_redist.x64.exe /quiet /norestart

# Install chocolatey
RUN @powershell -NoProfile -ExecutionPolicy unrestricted -Command "(iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))) >$null 2>&1"

RUN choco install git 7zip -y
RUN choco install cmake --installargs 'ADD_CMAKE_TO_PATH=""System""' -y

ADD cleanup-vcpkg.ps1 /cleanup-vcpkg.ps1

# Install vcpkg
RUN git clone https://github.com/Microsoft/vcpkg.git c:\vcpkg

CMD [ "cmd.exe" ]
