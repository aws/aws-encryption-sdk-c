# CBMC Batch

Running CBMC Batch jobs for a project.

## Expected Directory Structure

    project
    │   ...   
    │
    └───.cbmc-batch
    │   │   ...
    │   │
    │   └───jobs
    │       └───job1
    │       │   |    Makefile
    │       │   |    cbmc-batch.yaml
    │       └───job2
    │       │   |    Makefile
    │       │   |    cbmc-batch.yaml
    │       ...

It is expected that the repository contains a directory `.cbmc-batch`, which itself contains a directory `jobs`. Each directory in `.cbmc-batch/jobs` should correspond to a CBMC Batch job. Each job directory must contain a `Makefile` to be used by CBMC Batch to build the goto for CBMC and a `cbmc-batch.yaml` file to provide CBMC Batch options and provide an expected substring in the result of the CBMC run.

## Configuring the CBMC Version

Many proofs may require particular versions of CBMC. The version of CBMC to use for a particular job is specified by the tar file provided in the `cbmcpkg` field of the job's `cbmc-batch.yaml` file. The tar file is expected to be in the S3 Bucket that CBMC Batch uses. In particular, if `cbmcpkg: cbmc-ubuntu16.tar.gz` is provided in the `cbmc-batch.yaml` file, then CBMC Batch expects to find a file `package/cbmc-ubuntu16.tar.gz` in the S3 Bucket.

When the tar file is expanded, it is expected to produce a directory `cbmc` containing binaries `cbmc`, `goto-analyzer`, `goto-cc`, `goto-diff`, and `goto-instrument` that will run on the OS specified for the job (provided as the `jobos` in `cbmc-batch.yaml`). These binaries can produced by installing CBMC. If you install CBMC from source, then each binary `bin_name` will be located in `cbmc/src/bin_name/bin_name`, where `cbmc` is the name of the directory that CBMC was cloned into.

## Running Locally

In order to start the CBMC Batch jobs and check results locally, you need to have installed CBMC Batch and need to have the tar file containing versions of CBMC you want to use to your S3 bucket (see above).

You can start the CBMC Batch jobs locally by running

    bash cbmc-batch.sh --start

You can then check CBMC Batch results locally by running

	bash cbmc-batch.sh --end

This will run until all the jobs have finished and output results in `results.txt`.

You can clean up the local CBMC Batch bookkeeping files by running

    bash cbmc-batch.sh --cleanup
