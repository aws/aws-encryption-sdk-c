We use prebuilt docker images on windows, because configuring the build
environment (including building dependencies) takes upwards of an hour to
perform from scratch. This also gives us more precise control of the version
of MSVC that is in our build environment as well.

As a side effect of this, the codebuild environment takes longer to provision
(~20 minutes), but this is still far shorter than installing our dependencies
from scratch.

## Building Windows Docker Images and Uploading them to AWS Elastic Container Service
### Prereqs
* Windows with Containers (Any Windows 10 install with the Anniversary update will do)
* Docker
* AWS CLI

### Building the Image

Run build.ps1:

    powershell .\build.ps1

After the build finishes, you can run and test the image by running:

    docker run -it vs2015
      --or--
    docker run -it vs2017

To emulate the tests run by AWS CodeBuild, execute the following:

    git clone -b v1.0.0 --depth 1 https://github.com/aws/aws-encryption-sdk-c.git
    cd aws-encryption-sdk-c\codebuild
    .\codebuild\common-windows.bat

When you are satisfied the image is to your liking, simply exit the container.

### Publishing the Image

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
