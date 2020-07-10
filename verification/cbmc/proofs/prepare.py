#!/usr/bin/env python3
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions
# and limitations under the License.


"""Prepare the source tree for proofs in continuous integration."""


import os
import pathlib
import subprocess


MAKEFILE = "Makefile"
CBMC_BATCH_YAML = "cbmc-batch.yaml"


def create_cbmc_batch_yaml(folder):
    """Run make to create cbmc-batch.yaml in folder."""

    try:
        subprocess.run(
            ["make", "-B", CBMC_BATCH_YAML],
            cwd=folder,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True
        )
    except subprocess.CalledProcessError as error:
        raise UserWarning("Failed to create {} in {}: "
                          "command was '{}': "
                          "error was '{}'"
                          .format(CBMC_BATCH_YAML, folder,
                                  ' '.join(error.cmd),
                                  error.stderr.strip())) from None


def create_cbmc_batch_yaml_files(root='.'):
    """Create cbmc-batch.yaml in all directories under root."""

    for folder, _, files in os.walk(root):
        if CBMC_BATCH_YAML in files and MAKEFILE in files:
            create_cbmc_batch_yaml(folder)


def delete_common_yamls():
    """
    Delete cbmc-batch.yaml files from all C-Common proofs. C-Common contains
    proofs, but we don't want the CI for E-SDK to run them. This is a stopgap
    measure until we deploy a new CI that can avoid having to do this.
    """
    cbmc_dir = (pathlib.Path(__file__)).resolve().parent.parent
    for root, _, fyles in os.walk(cbmc_dir / "aws-c-common"):
        if "cbmc-batch.yaml" in fyles:
            os.unlink(os.path.join(root, "cbmc-batch.yaml"))



def prepare():
    """Prepare the source tree for proofs in continuous integration."""

    create_cbmc_batch_yaml_files()
    delete_common_yamls()


if __name__ == "__main__":
    prepare()
