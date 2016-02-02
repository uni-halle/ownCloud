# Decrypt OwnCloud files

## License

MIT. (See LICENSE.)

## Requirements

`python-cryptography` with the OpenSSL backend.

## Usage

This script has a lot of options. Like, a *lot*.
However, they are structured in a fairly straightforward manner.

### Unpacking a single file

If you just want to unpack a single file without having to deal with templates, you can give explicit paths for all keys and files using the `-e`, `-u`, `-s`, and `-f` options.
By default, the file will be written to stdout; use `-o` to specify an output file.
Please keep in mind that you cannot unpack multiple files this way, as encrypted files have per-file share and file keys.

#### Example

	$ ls
	encrypted.fkey	encrypted.skey	encrypted.txt	userkey.pem
	$ decrypt_file.py -e encrypted.txt -o decrypted.txt -u userkey.pem -s encrypted.skey -f encrypted.fkey
	Decrypting encrypted.txt...
	$ ls
	decrypted.txt	encrypted.fkey	encrypted.skey	encrypted.txt	userkey.pem


### Templates

You can specify the conventions your filenames adhere to by using *template strings*.
This allows you to process multiple files in a single run.
A template string tells the program where to look for a certain file (either encrypted file, or a keyfile of any sort).
Template strings can contain three *placeholders*:

- `$user`: The username (=first) argument you gave to the script
- `$ef`: The enc_file (=second) argument you gave to the script
- `$ef_fd`: Same as `$ef`, but with the first occurrence of `files/` removed

Please bear in mind that the template processing is done entirely in Python:
You should put your templates in single quotes so your shell doesn't process them.

The various templates are:

- `--ef-template`: Template for encrypted input files.
- `--of-template`: Template for decrypted output files.
- `--uk-template`: Template for user keys.
- `--sk-template`: Template for file share keys.
- `--fk-template`: Template for file keys.

**ATTENTION:** If you do not specify an output template, the files will all be written to stdout by default.
If you use the `-o` option, the files will all be written to that file.
In either case, a warning message will be printed to stderr.

#### Example

	# User keys have the form <user> + '.key'
	# Share keys have the form <enc_file> + '.' + <user> + '.skey'
	# File keys have the form <enc_file> + '.key'
	# All other templates should keep their defaults
	$ decrypt_file.py -U '$user.key' -S '$ef.$user.skey -F $ef.key testuser encrypted.txt

### Template defaults

There are three sets of default templates:

1. Default (no argument): The same as in [`uni-halle/owncloud/local-decryption/decrypt-file`](https://github.com/uni-halle/ownCloud/blob/master/local-decryption/decrypt-file)
2. `-A`: The same as in [`uni-halle/owncloud/local-decryption/decrypt-file-alternate`](https://github.com/uni-halle/ownCloud/blob/master/local-decryption/decrypt-file)
3. `-T`: Simple defaults useful for testing

Even if you use one of the default template sets, you can still override a template using the `-E`, `-O`, `-U`, `-S`, and `-F` options.

#### Example

	$ ls
	encrypted.txt.key	encrypted.txt.testuser.shareKey	encrypted.txt	testuser.pKeypem
	# Use the test defaults
	# But override the output file template
	$ decrypt_file.py -T -O '$ef.DECRYPTED' encrypted.txt
	Decrypting encrypted.txt...
	$ ls
	encrypted.DECRYPTED	encrypted.txt	encrypted.txt.key	encrypted.txt.testuser.shareKey	testuser.pKeypem
