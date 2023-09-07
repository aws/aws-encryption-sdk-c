#!/bin/bash

for x in $(cat files); do
    perl -pe "s/XXXX/$x/" viewer-tmpl.json > $x/cbmc-viewer.json
done
