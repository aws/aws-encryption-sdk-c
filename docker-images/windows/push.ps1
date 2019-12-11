# This is a ECS repository in our CI account
$ECS_REPO="636124823696.dkr.ecr.us-west-2.amazonaws.com/windows-docker-images"

Invoke-Expression -Command (Get-ECRLoginCommand -Region us-west-2).Command

docker tag vs2015 ${ECS_REPO}:vs2015-$(Get-Date -UFormat %Y%m%d-%H)
docker tag vs2017 ${ECS_REPO}:vs2017-$(Get-Date -UFormat %Y%m%d-%H)

docker push ${ECS_REPO}:vs2017-$(Get-Date -UFormat %Y%m%d-%H)
docker push ${ECS_REPO}:vs2015-$(Get-Date -UFormat %Y%m%d-%H)

