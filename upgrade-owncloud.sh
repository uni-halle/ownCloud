#!/bin/bash 

desiredUser=www-data
apacheRootLink=cloud.uni-halle.de-apache
setupScript=after-update.sh
upgradeScript=occ
php=$(which php)

# check arguments
[ -z "$@" ] && { >&2 cat <<USG
Switch the OC-Version and upgrade the Application. Must be run as Webserver user (www-data).
Usage:
  $0 [new oc core directory]

USG
exit -1
}

# check for user
[ "$(whoami)" != "$desiredUser" ] && { >&2 cat <<who
This script has to be run as ${desiredUser}.
Use 'sudo -u ${desiredUser} $0 ...' to do so.

who
exit 1
}

# check target
newCore=$1
[ ! -d $newCore ] && { >&2 cat <<coreDir
The directory you've provided '$newCore' does not exist."

coreDir
exit 2
}
# check for upgrade script in $newCore
[ ! -f "$newCore/$upgradeScript" ] && { >&2 cat <<occFile
The directory does not contain the ${upgradeScript} script.

occFile
exit 3
}

## start
rm $apacheRootLink
ln -s $newCore $apacheRootLink && (. $setupScript) && $php $apacheRootLink/$upgradeScript upgrade
exit $?
