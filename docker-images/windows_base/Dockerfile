# escape=`
# latest is not a tag used by Microsoft see https://hub.docker.com/_/microsoft-windows-servercore
# Note you must use a server version compatible with CodeBuild, ask or refer to their vended Windows Dockerfile.
FROM mcr.microsoft.com/windows/servercore:ltsc2016

LABEL Description="Base image for Build Testing"
LABEL Vendor="AWS"
LABEL Version="1.0"

ADD https://download.microsoft.com/download/6/A/A/6AA4EDFF-645B-48C5-81CC-ED5963AEAD48/vc_redist.x64.exe /vc_redist.x64.exe
RUN start /wait C:\vc_redist.x64.exe /quiet /norestart

# Install chocolatey
# which needs TLS1.2 for powershell too be enabled. it's 2020.
RUN @powershell -NoProfile -ExecutionPolicy unrestricted -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 ; (iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))) >$null 2>&1"


RUN choco install git 7zip -y
RUN choco install cmake --installargs 'ADD_CMAKE_TO_PATH=""System""' -y

ADD cleanup-vcpkg.ps1 /cleanup-vcpkg.ps1

# Install vcpkg
RUN git clone https://github.com/Microsoft/vcpkg.git c:\vcpkg

CMD [ "cmd.exe" ]
