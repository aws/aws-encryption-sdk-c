# Docker images for testing

## How are the Docker images used ?

The project uses AWS CodeBuild to launch tests on GitHub pull request submission, with prebuilt Docker containers stored as artifacts in ECR.

## How are the Docker images built ?

A CodePipeline setup will fire either on a webhook or schedule and rebuild the docker containers, uploading them to ECR.  The automation to get Windows images to built under this pipeline is complex and not currently implemented.  Images can also be built manually.

## Linux Docker file layout

Each distribution folder contains a script directory (`bin`) intended for use by a build job to install dependencies and setup the docker image for future testing.
The  version folder contain a Dockerfile and buildspec.yml used by CodeBuild to generate the images.
The docker-compose.yml file allows some abstraction of installed version dependencies.  The file is generated with the `gen_compose.py` script manually when OS or dependency version changes are needed.

## Manually Building Linux Docker Images

As an example, `docker-compose build ubuntu_18.04_OpenSSL_1_1_0-stable` would build Ubuntu 18.04 with OpenSSL 1.1.0 and all the other necessary prerequisites installed.


## Windows

For Windows, there is a base docker image with two additional layers created on top of the base for different versions of Visualcpp.

Windows builds do not utilize docker compose. The Windows building process is not yet automated.

### Manually Building Windows Docker Images and Uploading them to AWS Elastic Container Repository 
#### Prereqs for the build host
* EC2 Windows instance with Containers (must match CodeBuild hosts: 10.0.14393 build hosts as of this writing).
* Docker 
* AWS CLI

Run build.ps1:

    powershell .\build.ps1

After the build finishes, you can run and test the image by running:

    docker run -it vs2015
      --or--
    docker run -it vs2017

To emulate the tests run by AWS CodeBuild, execute the following (note the version of VisualStudio installed):

    git clone -b v1.0.0 --depth 1 https://github.com/aws/aws-encryption-sdk-c.git
    cd aws-encryption-sdk-c\codebuild
    .\codebuild\common-windows.bat -DBUILD_SHARED_LIBS=ON -G "Visual Studio 15 2017"

When you are satisfied the image is to your liking, simply exit the container.

#### Publishing the Image

If you are publishing to your own account, update the `ECS_REPO` value in
`push.ps1`. You can find the correct URI in the AWS Console for your ECR
repository.

Once you have `ECS_REPO` set properly, and you have configured your Powershell
AWS CLI credentials correctly, simply _source_ push.ps1:

    . .\push.ps1

Note that because powershell CLI credentials are per-powershell-session, it's
important to use dot-sourcing if you use the `Set-AWSCredential` cmdlet to configure
your credentials. If you're using EC2 Instance Roles, then it's not strictly necessary
to dot-source the script.
