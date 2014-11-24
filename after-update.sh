#!/bin/bash
target=cloud.uni-halle.de-apache/
cd $target
rm config/config.php
ln -s ../../config.php config/config.php
ln -s ../../mlu-theme themes/mlu
