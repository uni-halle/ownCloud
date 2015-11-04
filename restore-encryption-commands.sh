#!/bin/bash

### !!! needs to be run as webserver-user

### !!! EDIT this pattern to match all user directories in OC data directory
userpattern='^(.{5}|cloud-administration-user)$'
# recover user keys
for username in $(ls -1tr|egrep -o $userpattern); do
  backup=$(ls -1tr $username|egrep '^encryption_migration_backup'|head -n1)
  if [ "x" != "x$backup" ]; then
    # echo "$username --> $backup"
    # create backup of broken state, just in case
    echo "mv $username/files_encryption $username/files_encryption.broken_1"
    # recreate the renamed folder
    echo "mkdir -p $username/files_encryption"
    # recover the pre-update state
    echo "cp -r $username/$backup/* $username/files_encryption"
    echo "ln -s keyfiles $username/files_encryption/keys"
  fi
done

# recover global encryption directories
globbackup=$(ls -1tr|egrep '^encryption_migration_backup'|head -n1)
for bu in $(ls -1 $globbackup); do
  echo "mv $bu $bu.broken"
  echo "cp -r $globbackup/$bu $bu"
done


