Start-Transcript -path .\build.log

docker build -m6g -t vs2015 .\visualcpp2015
docker build -m6g -t vs2017 .\visualcpp2017

