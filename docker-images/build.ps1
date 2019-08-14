Start-Transcript -path .\build.log

docker build -m6g -t aws_encryption/windows_base:1809-amd64 -f .\windows_base\Dockerfile .
docker build -m6g -t vs2015 -f .\visualcpp2015\Dockerfile .
docker build -m6g -t vs2017 -f .\visualcpp2017\Dockerfile .

