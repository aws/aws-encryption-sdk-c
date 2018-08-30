#!/bin/sh

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -u
set -x

if [ "$#" -eq 0 ]; then
    echo "Specify option -s to start jobs, -e to end jobs, and -c to cleanup bookkeeping"
fi

while getopts ":sec" opt; do
    case $opt in
        s ) # Start CBMC Batch Jobs
            for job in jobs/*/; do
                job=${job%/} #remove trailing slash
                job=${job#*/} #job name
                echo "Starting job $job"
                cbmc-batch \
                    --no-report \
                    --no-coverage \
                    --wsdir jobs/$job \
                    --srcdir ../ \
                    --jobprefix $job-local \
                    --yaml jobs/$job/cbmc-batch.yaml
            done
            ;;
        e ) # Check CBMC Batch Job Results
            result="results.txt"
            if [ -f $result ]; then
                rm $result
            fi
            for Makefile in Makefile-*-local-*; do
                make -f $Makefile monitor
                make -f $Makefile copy
                dir=${Makefile#*-} # directory name from copy
                job=${dir%-local-*-*} # original job name
                check="$( python check_result.py $dir jobs/$job/cbmc-batch.yaml )"
                echo "$job: $check" >> $result
            done
            ;;
        c ) # Cleanup
            for Makefile in Makefile-*-local-*; do
                make -f $Makefile cleanup
            done
            ;;
        \?)
            echo "Specify option -s to start jobs, -e to end jobs, and -c to cleanup bookkeeping"
    esac
done
