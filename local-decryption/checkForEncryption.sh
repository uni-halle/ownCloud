#!/bin/bash

file="$1"

matches=`head -c1k "${file}"|egrep -o "cipher:[^:]+"|wc -l `
if [ ${matches} -ne 0 ]; then
	echo "${file}"
	exit 0
fi
exit 1
