This directory contains the configuration for our Linux-based docker images
used for codebuild builds, as well as the build-time scripts for both linux and
windows.

To update the repository, set up appropriate AWS credentials, and run
bin/push-docker.sh . For test purposes, the ECS_REPOSITORY environment variable
can be set to push to an alternate repository, and/or one in a different account.
