#!/bin/bash
##
## Copyright (c) 2020 Bitdefender
## SPDX-License-Identifier: Apache-2.0
##

set -euo pipefail
IFS="
"

cpus=`grep -c ^processor /proc/cpuinfo`
size=`stat -c %s $1`
ret=$(($size/$cpus - 1))

log=`realpath $1`

mkdir -p output

split -b $ret -d $log output/

for f in output/*; do { awk '{printf "%s\n", $5}' $f | uniq | sort | uniq | grep "\[.*" > $f.uniq & } ; done
wait

cat output/*.uniq | uniq | sort | uniq | sed -e "s/\[//" -e "s/\]//"> output/results.uniq

xargs -a output/results.uniq -P$cpus -I % bash -c "fgrep % $log > output/%.log"
