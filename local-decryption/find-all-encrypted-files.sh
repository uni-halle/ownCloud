#!/bin/bash

for user in $(ls -A ../oc-data)
do
	echo $user >&2
	if [ -d "../oc-data/${user}" ]
	then
		./find-encrypted-files.sh $user 2>/dev/null
	fi
done

