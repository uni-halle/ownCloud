#!/bin/bash
target=cloud.uni-halle.de-apache/
cd $target
rm config/config.php
#cp ../config-copy.php config/config.php
ln -sr ../config-prod.php config/config.php
ln -sr ../mlu-theme themes/mlu
