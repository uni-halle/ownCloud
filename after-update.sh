#!/bin/bash
target=cloud.uni-halle.de-apache/
cd $target
rm config/config.php
cp ../config.php config/
ln -s ../../mlu-theme themes/mlu
