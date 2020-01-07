#!/usr/bin/env python3
# -*- coding: utf-8 -*-
copywrite = """# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
"""

import logging
import os
import sys
import yaml

from awacs.aws import Statement, PolicyDocument, Principal
from awacs.sts import AssumeRole
from collections import defaultdict
from troposphere import Template, Ref
from troposphere.codebuild import Artifacts, Environment, Source, Project
from troposphere.iam import PolicyType, Role

logging.basicConfig(level=logging.DEBUG)

# Docker built matrix os distro/OS/SSL version (excludes macOS and windows)
distros = {"ubuntu": ['18.04', '16.04', '14.04'], "amazonlinux": ['2018.03', '2.0'], "centos": ['7']}
open_ssl_versions = ['OpenSSL_1_1_1-stable', 'OpenSSL_1_1_0-stable', 'OpenSSL_1_0_2-stable']
gcc = ['DEFAULT', '6']

# CodeBuild needs a map of OS -> ECR
ecr_map = dict({'ubuntu': '636124823696.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images',
                'amazonlinux': '636124823696.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images',
                'centos': '636124823696.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images',
                'windows': '636124823696.dkr.ecr.us-west-2.amazonaws.com/windows-docker-images',
                })


def populate_template(openssl_tag: str, distro: str, tag: str) -> defaultdict:
    """ Populate the body section of a docker-compose yaml file """
    return {'{}_{}_{}'.format(distro, tag, openssl_tag): {
        'build': {
            'args': {'OPENSSL_TAG': '{}'.format(openssl_tag)},
            # TODO: ARG BUILD_DATE
            'context': './{}'.format(distro),
            'dockerfile': '{}/Dockerfile'.format(tag)},
        'image': '${REPOSITORY_URI}' + f':{distro}_{tag}_{openssl_tag}'
    }}


def compose() -> dict:
    """ For each Distro,version and openssl version, create a stanza in a docker-compose config structure."""
    final = {'version': "3.7", 'services': {}}
    for distro, release in distros.items():
        for tag in release:
            for ssl_ver in open_ssl_versions:
                final['services'].update((populate_template(openssl_tag=ssl_ver, distro=distro, tag=tag)))
    return final


def buildspec() -> dict:
    """ For each Distro,version and openssl version, create a stanza in a docker-compose config structure."""
    final = dict()
    for distro, release in distros.items():
        for tag in release:
            for ssl_ver in open_ssl_versions:
                final[distro + '/' + tag + '/buildspec_' + ssl_ver] = create_buildspec(openssl_tag=ssl_ver,
                                                                                       distro=distro,
                                                                                       tag=tag)
    return final


def create_buildspec(openssl_tag: str, distro: str, tag: str) -> dict:
    """ For each Distro,version and openssl version, create a buildspec config structure."""
    return {'version': "0.2",
            'phases': {
                'install': {
                    'runtime-versions': {
                        'docker': 18
                    },
                    'commands': [
                        'echo Logging in to Amazon ECR...',
                        'aws --version',
                        '$(aws ecr get-login --region $AWS_DEFAULT_REGION --no-include-email)',
                        'REPOSITORY_URI=636124823696.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images',
                        'COMMIT_HASH=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c 1-7)'
                    ]
                },
                'build': {
                    'labels': {
                        "openssl_tag": openssl_tag,
                        "distro": distro,
                        "distro_release": tag,
                        "description": f"Buld testing image for {distro}_{tag}"
                    },
                    'commands': [
                        "echo Building Docker image at `date`",
                        f"docker-compose -f docker-images/docker-compose.yml build {distro}_{tag}_{openssl_tag}"
                    ]
                },
                'post_build': {
                    'commands': ['echo Build completed on `date`',
                                 'echo Pushing the Docker images',
                                 f'docker push $REPOSITORY_URI:{distro}_{tag}_{openssl_tag}'
                                 ]}
            }
            }


def codebuild_iam_roles() -> Template:
    """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKeyWithoutPlaintext"
                ],
                "Resource": [
                    "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2",
                    "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
                ]
            }
        ]
    }
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:logs:us-west-2:636124823696:log-group:/aws/codebuild/csdk-trusty-gcc4x-x64",
                    "arn:aws:logs:us-west-2:636124823696:log-group:/aws/codebuild/csdk-trusty-gcc4x-x64:*"
                ],
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ]
            },
            {
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:s3:::codepipeline-us-west-2-*"
                ],
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation"
                ]
            }
        ]
    }

    :return:
    """
    cfnrole = Template()

    role_name = cfnrole.add_resource(Role("CESDKCodeBuildRole", AssumeRolePolicyDocument=PolicyDocument(
        Statement=[
            Statement(
                Effect="Allow",
                Action=[AssumeRole],
                Principal=Principal("Service", ["codebuild.amazonaws.com"])
            )
        ]
    )
  )
)


    cfnrole.add_resource(PolicyType(
        "CESDKCodebuildPolicy",
        PolicyName="ESDKC-TestResources",
        Roles=[Ref(role_name)],
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:logs:us-west-2:636124823696:log-group:/aws/codebuild/csdk-trusty-gcc4x-x64",
                    "arn:aws:logs:us-west-2:636124823696:log-group:/aws/codebuild/csdk-trusty-gcc4x-x64:*"
                ],
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ]}, {
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:s3:::codepipeline-us-west-2-*"
                ],
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation"
                ]
            }
            ]
        },
        DependsOn="CESDKCodeBuildRole"
    ))

    return cfnrole


def create_codebuild_jobs() -> defaultdict:
    result = defaultdict()
    artifacts = Artifacts(Type='NO_ARTIFACTS')

    for distro, release in distros.items():
        for tag in release:
            for ssl_ver in open_ssl_versions:
                for gcc_maj_ver in gcc:
                    full_target = '_'.join([distro, tag, ssl_ver, gcc_maj_ver])
                    # CodeBuild project names can not have dots.
                    # TODO: Test case for names with/without dots
                    no_dot_full_target = ''.join(full_target.split('.'))

                    environment = Environment(
                        ComputeType='BUILD_GENERAL1_SMALL',
                        Image=f'{ecr_map[distro]}:{distro}_{tag}_{ssl_ver}',
                        Type='LINUX_CONTAINER',
                        EnvironmentVariables=[{'Name': 'distro', 'Value': distro},
                                            {'Name': 'release', 'Value': tag},
                                            {'Name': 'gcc_maj_ver', 'Value': gcc_maj_ver},
                                            {'Name': 'openssl_ver', 'Value': ssl_ver}],
                    )

                    source = Source(
                        Location='https://github.com/aws/aws-encryption-sdk-c.git',
                        Type='GITHUB'
                    )

                    project = Project(
                        'esdkc',
                        Artifacts=artifacts,
                        Environment=environment,
                        Name=f'aws-encryption-sdk-c_{no_dot_full_target}',
                        ServiceRole="CESDKCodeBuildRole",
                        Source=source,
                    )
                    result[full_target] = Template()
                    result[full_target].set_version('2010-09-09')
                    result[full_target].add_resource(project)
    return result


def main(*argv):
    # TODO: check for isengard role...
    # if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_ACCESS_KEY_ID' in os.environ:

    logging.debug('Generating docker compose data structure.')
    docker_compose = compose()

    logging.debug('Createing docker-compose yaml file.')
    with(open("docker-compose.yml", "w")) as fh:
        fh.write(copywrite)
        fh.write(yaml.dump(docker_compose, default_style=None, default_flow_style=False, sort_keys=False))

    logging.debug('Creating Buildspec files for CodeBuild Projects.')
    all_buildspecs = buildspec()
    for target in all_buildspecs.keys():
        repo_tag_path = '/'.join(target.split('/')[:-1])
        if not os.path.isdir(repo_tag_path):
            os.mkdir(repo_tag_path)
        with(open(target + '.yml', "w")) as fh:
            fh.write(copywrite)
            fh.write(yaml.dump(all_buildspecs[target], default_style=None, default_flow_style=False, sort_keys=False))

    logging.debug('Creating IAM Role CloudFormation yaml.')
    iam_roles = codebuild_iam_roles()
    with(open(f'../codebuild/cfn/iam_roles.yml', "w")) as fh:
        fh.write(copywrite)
        fh.write(iam_roles.to_json())

    logging.debug('Creating CodeBuild CloudFormation yamls.')
    all_cfn = create_codebuild_jobs()
    for target in all_cfn.keys():
        with(open(f'../codebuild/cfn/{target}_cfn.yml', "w")) as fh:
            fh.write(copywrite)
            fh.write(all_cfn[target].to_json())


if __name__ == "__main__":
    main(sys.argv)
