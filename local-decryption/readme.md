server side file decryption for ownCloud
========================================

based on [ocdec](//github.com/arno01/ocdec) by `arno01`



This directory is ment to be an alias in the oc apache root to give users the option to decrypt their files.


# index.php

... uses the username and password of a user to decrypt a user private key just once using the script `decrypt-private-key`
The key is then stored in pem format to decrypt the files later.

# decrypt-user-files*
depending on the structure of the private keys you should use one of the two scripts to decrypt the files of a user after the private key decryption.

Typically one of the two works.

# decrypt-file*

Helper script to decrypt a single file to stdout, typically invoked by decrypt-user-files*

# find-all-encrypted-files.sh

is used in a cron to gather a list of encrypted files over the whole oc-data directory
