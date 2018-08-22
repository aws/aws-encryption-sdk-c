Start-Transcript -path .\build.log

$ECS_REPO="636124823696.dkr.ecr.us-west-2.amazonaws.com/windows-docker-images"

Invoke-Expression -Command (Get-ECRLoginCommand -Region us-west-2).Command

docker build -m6g -t ${ECS_REPO}:vs2015 .\visualcpp2015
docker build -m6g -t ${ECS_REPO}:vs2017 .\visualcpp2017

docker push ${ECS_REPO}:vs2017
docker push ${ECS_REPO}:vs2015

