#!/bin/bash

packages=$(cat <<EOF
  libapache2-mod-php5
  libav-tools
  libreoffice-writer
  php5-apcu
  php-mime-type
  php5-ldap
  smbclient
  php5-mysql
  php5-json
  php5-imagick
  php5-gd
  php5-curl
  postfix 
EOF
)
if [ "$#" -lt 1 ]; then
	bin=$(basename $0)
	if [ $EUID -ne 0 ]; then bin="sudo $bin"; fi
	echo "usage:"
	echo "  $bin install"
	echo
	echo "this would install following packages:"
	echo "$packages"
fi
if [[ "$1" = "install" ]]; then
	$(which apt-get) install $packages
fi
