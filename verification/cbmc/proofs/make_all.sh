#!/bin/bash -eu

for x in $(cat files); do
    echo $x
    cd $x
    make
    cd ..
done
