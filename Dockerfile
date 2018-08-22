FROM 636124823696.dkr.ecr.us-west-2.amazonaws.com/windows-docker-images:vs2015

ADD . c:/codebuild-tmp

RUN powershell -NoProfile -InputFormat None -Command `\
    cd c:/codebuild-tmp; `\
    .\codebuild\common-windows.bat -G \"Visual Studio 14 2015 Win64\"

RUN powershell -NoProfile -InputFormat None -Command `\
    cd c:/codebuild-tmp/build; `\
    ctest -V --output-on-failure