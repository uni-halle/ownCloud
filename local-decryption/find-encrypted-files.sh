#!/bin/bash

if [ $# -lt 1 ]; then
  echo "no user provided" >&2
  echo "USAGE: $0 <username>" >&2
  exit -1
fi

ocd=oc-data;
user=$1
singleFileChecker="./checkForEncryption.sh"
searchDir="../${ocd}/${user}/files"

find ${searchDir} -type f -exec $singleFileChecker "{}" ${searchDir} \; 

