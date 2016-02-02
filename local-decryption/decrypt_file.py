#!/usr/bin/env python3

# TODO:
# - Test suite
# - dry-run option

from argparse import ArgumentParser, RawDescriptionHelpFormatter
import base64
import logging
import os
import os.path as path
import re
from shutil import move
from string import Template
import subprocess
import sys
from tempfile import mkstemp
from textwrap import dedent

from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives.asymmetric import padding


# A "chunk" is a BASE64 encoded, encrypted piece of data that contains
# the payload (8168B) and a padded initialization vector (IV, 24B
# w/padding, 16B w/o padding).
CHUNK_SIZE = 8192


class NotEncryptedError(Exception):
    def __init__(self, filename):
        self.filename = filename

    def __str__(self):
        return repr(self.filename)


class EncryptedFileContext:
    def __init__(self,
            user,
            file,
            user_key_path=None,
            share_key_path=None,
            file_key_path=None):
        self.user = user
        self.file = file
        if user_key_path is None:
            self.user_key_path = path.join(os.getcwd(), self.user + ".pKey.pem")
        else:
            self.user_key_path = user_key_path

        common_path_component = path.join(
                os.getcwd(),
                self.user,
                "files_encryption",
                "keys",
                re.sub('files', '', self.file, count=1),
                user
        )

        if share_key_path is None:
            self.share_key_path = common_path_component + '.shareKey'
        else:
            self.share_key_path = share_key_path

        if file_key_path is None:
            self.file_key_path = common_path_component + '.fileKey'
        else:
            self.file_key_path = file_key_path

            self.backend = openssl_backend

    def _get_user_key(self):
        with open(self.user_key_path, 'rb') as key_file:
            user_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=self.backend
            )
        return user_key

    def _decrypt_share_key(self):
        user_key = self._get_user_key()
        with open(self.share_key_path, 'rb') as key_file:
            share_key = user_key.decrypt(
                    key_file.read(),
                    padding.PKCS1v15()
            )
        return share_key

    def _decrypt_file_key(self):
        share_key = self._decrypt_share_key()
        algorithm = algorithms.ARC4(share_key)
        cipher = Cipher(algorithm, mode=None, backend=self.backend)
        decryptor = cipher.decryptor()
        with open(self.file_key_path, 'rb') as key_file:
            file_key = decryptor.update(key_file.read())
        return file_key

    def _get_number_of_chunks(self):
        filesize = path.getsize(self.file)
        # The header chunk doesn't count
        num_chunks = filesize // CHUNK_SIZE - 1
        # There might be a remainder
        if filesize % CHUNK_SIZE > 0:
            num_chunks += 1
        return num_chunks

    @staticmethod
    def _parse_header(header):
        aes_256_cipher_header = b'HBEGIN:cipher:AES-256-CFB:HEND'
        aes_128_cipher_header = b'HBEGIN:cipher:AES-128-CFB:HEND'

        if header[:len(aes_256_cipher_header)] == aes_256_cipher_header:
            file_key_size = 32
        elif header[:len(aes_128_cipher_header)] == aes_128_cipher_header:
            file_key_size = 16
        else:
            raise NotEncryptedError(self.file)

        return file_key_size

    def _yield_chunk(self):
        with open(self.file, 'rb', buffering=CHUNK_SIZE) as f:
            file_key_size = self._parse_header(f.read(CHUNK_SIZE))

            file_key = self._decrypt_file_key()
            # For reasons unfathomable, we only use the first 32/16 bits of the
            # 44-byte key. Probably in accordance with the PHP openssl_decrypt
            # function.
            algorithm = algorithms.AES(file_key[:file_key_size])

            while f:
                chunk = memoryview(f.read(CHUNK_SIZE))
                if chunk == b'':
                    # Implicitly raises StopIteration (with return value)
                    return
                payload_base64, iv_padded = chunk[:-24], chunk[-24:]
                if not iv_padded[:6] == b'00iv00' and iv_padded[-2:] == b'xx':
                    raise NotEncryptedError(f)
                payload = base64.b64decode(payload_base64)
                iv = iv_padded[6:22].tobytes()
                cipher = Cipher(
                        algorithm,
                        modes.CFB(iv),
                        self.backend
                )
                decryptor = cipher.decryptor()
                yield decryptor.update(payload)

    def _yield_multiple_chunks(self, num_chunks=1):
        decrypted = []
        for chunk in self._yield_chunk():
            decrypted.append(chunk)
            # Only yield if we actually have a valid threshold (>=1)
            if (not (num_chunks <= 0)) and (len(decrypted) >= num_chunks):
                yield b''.join(decrypted)
                decrypted = []
        # There might still be some chunks left in decrypted
        if decrypted:
            yield b''.join(decrypted)

    def decrypt_file(self):
        return b''.join([chunk for chunk in self._yield_chunk()])


def parse_args():
    a = ArgumentParser(
            description="A program for decrypting files encrypted by OwnCloud",
            formatter_class=RawDescriptionHelpFormatter,
    )
    a.add_argument('user',
            help="User name"
    )
    a.add_argument('enc_file',
            nargs='+',
            help=("Path to encrypted file\n"
                    "(before template processing, unless --enc-file is used)"
            )
    )
    num_chunks_default = 1
    a.add_argument('-n', '--num-chunks',
            type=int,
            default=num_chunks_default,
            metavar='INT',
            help=("Number of chunks written at once. If 0 or negative, keep "
                    "in memory and only write once entire file has been "
                    "processed (Default: {})".format(num_chunks_default)
            )
    )
    alt_defaults = a.add_mutually_exclusive_group()
    alt_defaults.add_argument('-A', '--alternate-defaults',
            action='store_true',
            help=("Use alternate default templates as defined in "
                    "decrypt-file-alternate:\n"
                    "'${user}/files_encryption/share-keys/${ef_nofd}.${user}.shareKey' "
                    "for share key,\n"
                    "'${user}/files_encryption/keyfiles/${ef_nofd}.key' "
                    "for file key"
            )
    )
    alt_defaults.add_argument('-T', '--testing-defaults',
            action='store_true',
            help=("Use default templates useful for testing:\n"
                    "'${ef}' for encrypted file,\n"
                    "'${ef}.dec' for output file,\n"
                    "'${user}.pKey.pem' for user key,\n"
                    "'${ef}.${user}.shareKey' for share key,\n"
                    "'${ef}.key' for file key"
            )
    )

    verbosity_options = a.add_mutually_exclusive_group()
    verbosity_options.add_argument('-q', '--quiet',
            dest='loglevel',
            action='store_const',
            const=-1,
            help="Suppress all output"
    )
    verbosity_options.add_argument('-v', '--verbose',
            dest='loglevel',
            action='count',
            help='Display more output (can be given multiple times)'
    )

    tmpls_and_file_handling = a.add_argument_group(
            title="File and template handling",
            description=dedent("""
                    The following variables are usable in templates:

                    ${user}: User (= first argument)
                    ${ef}: Path to encrypted file (= second argument)
                    ${ef_nofd}: Path to encrypted file, with first occurrence of the "files/"
                      directory removed

                    You cannot use the explicit file options (-o, -u, -s, -f)
                    if you have multiple input files, but you can use -e.
                    """
            )
    )

    enc_file_options = tmpls_and_file_handling.add_mutually_exclusive_group()
    ef_template_default = '${user}/${ef}'
    enc_file_options.add_argument('-E', '--ef-template',
            metavar='TMPL',
            default=None,
            help=("Template for encrypted file.\n"
                    "(Default: {})".format(ef_template_default)
            )
    )
    enc_file_options.add_argument('-e', '--enc-file',
            action='store_true',
            help=("Treat path to encrypted file as explicit. "
                    "Not usable together with -E."
            )
    )

    out_file_options = tmpls_and_file_handling.add_mutually_exclusive_group()
    out_file_options.add_argument('-O', '--of-template',
            metavar='TMPL',
            default=None,
            help=("Template for output file.\n"
                    "If the output file resolves exactly to the input file,\n"
                    "it is decrypted to a temporary path and moved into place\n"
                    "afterwards, overwriting the input file.\n"
            )
    )
    out_file_options.add_argument('-o', '--out-file',
            default=None,
            metavar='FILE',
            help=("Explicit path to output file. Not usable together with -O.\n"
                    "If it resolves exactly to the input file, it is\n"
                    "decrypted to a temporary path and moved into place\n"
                    "afterwards, overwriting the input file. "
                    "(Default: write to stdout)"
            )
    )

    user_key_options = tmpls_and_file_handling.add_mutually_exclusive_group()
    uk_template_default = '${user}.pKey.pem'
    user_key_options.add_argument('-U', '--uk-template',
            metavar='TMPL',
            default=None,
            help=("Template for user key.\n"
                    "(Default: {})".format(uk_template_default)
            )
    )
    user_key_options.add_argument('-u', '--user-key',
            metavar='FILE',
            help="Explicit path to user key. Not usable together with -U."
    )

    share_key_options = tmpls_and_file_handling.add_mutually_exclusive_group()
    sk_template_default = '${user}/files_encryption/keys/${ef_nofd}/${user}.shareKey'
    share_key_options.add_argument('-S', '--sk-template',
            metavar='TMPL',
            default=None,
            help=("Template for file share key.\n"
                    "(Default: {})".format(sk_template_default)
            )
    )
    share_key_options.add_argument('-s', '--share-key',
            metavar='FILE',
            help=("Explicit path to file share key. "
                    "Not usable together with -S."
            )
    )

    file_key_options = tmpls_and_file_handling.add_mutually_exclusive_group()
    fk_template_default = '${user}/files_encryption/keys/${ef_nofd}/fileKey'
    file_key_options.add_argument('-F', '--fk-template',
            metavar='TMPL',
            default=None,
            help=("Template for encrypted file.\n"
                    "(Default: {})".format(fk_template_default)
            )
    )
    file_key_options.add_argument('-f', '--file-key',
            metavar='FILE',
            help="Explicit path to file key. Not usable together with -F."
    )

    args = a.parse_args()

    # Set loglevel directly in args namespace
    args.loglevel = _set_loglevel_from_verbosity(args.loglevel)

    # Set alternate defaults if specified
    if args.alternate_defaults:
        sk_template_default = '${user}/files_encryption/share-keys/${ef_nofd}.${user}.shareKey'
        fk_template_default = '${user}/files_encryption/keyfiles/${ef_nofd}.key'
    elif args.testing_defaults:
        ef_template_default = '${ef}'
        of_template_default = '${ef}.dec'
        uk_template_default = '${user}.pKey.pem'
        sk_template_default = '${ef}.${user}.shareKey'
        fk_template_default = '${ef}.key'

    # Set templates to default if no actual value was provided
    #
    # The output file must be handled differently, as we want to write to
    # stdout by default
    args.ef_template = args.ef_template or ef_template_default
    args.uk_template = args.uk_template or uk_template_default
    args.sk_template = args.sk_template or sk_template_default
    args.fk_template = args.fk_template or fk_template_default

    return args


def _set_loglevel_from_verbosity(loglevel):
    """
    Turns an int or the value None into a valid loglevel.
    """
    # Is None if no verbosity options are set
    loglevel = loglevel or 0
    loglevels = {
            -1: logging.ERROR,    # -q
            0: logging.WARN,      # no options
            1: logging.INFO,      # -v
            2: logging.DEBUG      # -vv
    }
    return loglevels[loglevel]


def _mungle_template(tmpl, tmpl_vars):
    return Template(tmpl).substitute(**tmpl_vars)


def _process_template_vars(user, enc_file):
    """
    Takes the *original* user and enc_file arguments and produces a dict of
    template vars from them.
    """
    tmpl_vars = {
            'ef_nofd': re.sub('files/', '', enc_file, count=1),
            'ef': enc_file,
            'user': user
    }
    return tmpl_vars

def _process_paths(original_paths, tmpl_vars):
    """
    Takes a dictionary with values of the form (orig_path, template).

    If orig_path evaluates to False, it is instead constructed from the
    template string and tmpl_vars.
    """
    processed_paths = {}
    for (key, (orig_path, tmpl)) in original_paths.items():
        if not orig_path:
            normalized_path = path.normpath(
                    _mungle_template(tmpl, tmpl_vars)
            )
        else:
            normalized_path = path.normpath(orig_path)
        processed_paths[key] = normalized_path
    return processed_paths


def _process_output_path(out_file, of_template, tmpl_vars):
    if out_file is not None:
        # User specified output file
        return out_file
    elif of_template is not None:
        # User specified output template
        return _mungle_template(of_template, tmpl_vars)
    else:
        # User didn't specify anything
        return '-'


def main():
    args = parse_args()
    logging.basicConfig(
            level=args.loglevel,
            format='%(message)s',
            stream=sys.stderr
    )
    # Abort if multiple input files are used with any of -s or -f
    if len(args.enc_file) > 1 and any([args.share_key,
                                       args.file_key]):
        logging.critical("You cannot use multiple input files together with "
                "explicit key files. Use templates instead.")
        sys.exit(1)

    if len(args.enc_file) > 1 and args.out_file is not None:
        logging.warn("You have multiple input files and a single output file. "
                "The decrypted data will be concatenated.")

    for enc_file in args.enc_file:
        tmpl_vars = _process_template_vars(args.user, enc_file)
        original_paths = {
                'ef': (enc_file, args.ef_template),
                'uk': (args.user_key, args.uk_template),
                'sk': (args.share_key, args.sk_template),
                'fk': (args.file_key, args.fk_template)
        }
        processed_paths = _process_paths(original_paths, tmpl_vars)
        processed_paths['of'] = _process_output_path(args.out_file, args.of_template, tmpl_vars)

        context = EncryptedFileContext(
                args.user,
                processed_paths['ef'],
                processed_paths['uk'],
                processed_paths['sk'],
                processed_paths['fk']
        )

        logging.info("Decrypting {}...".format(processed_paths['ef']))
        logging.debug("User key: {}".format(processed_paths['uk']))
        logging.debug("Share key: {}".format(processed_paths['sk']))
        logging.debug("File key: {}".format(processed_paths['fk']))

        try:
            if args.out_file == '-':
                logging.debug("Output to stdout")
                # sys.stdout itself doesn't take binary data, so we have to use the
                # underlying buffer directly
                if args.num_chunks <= 0:
                    sys.stdout.buffer.write(context.decrypt_file())
                elif args.num_chunks == 1:
                    for chunk in context._yield_chunk():
                        sys.stdout.buffer.write(chunk)
                else:
                    for chunks in context._yield_multiple_chunks(args.num_chunks):
                        sys.stdout.buffer.write(chunks)

            elif processed_paths['ef'] == processed_paths['of']:
                (tmp_fd, tmpfile_path) = mkstemp()
                logging.debug("Writing to temporary file {}".format(tmpfile_path))
                with open(tmp_fd, 'wb', buffering=CHUNK_SIZE) as tmp_file:
                    if args.num_chunks <= 0:
                        tmp_file.write(context.decrypt_file())
                    elif args.num_chunks == 1:
                        for chunk in context._yield_chunk():
                            tmp_file.write(chunk)
                    else:
                        for chunks in context._yield_multiple_chunks(args.num_chunks):
                            tmp_file.write(chunks)
                logging.debug("Overwriting input file {}".format(processed_paths['of']))
                move(tmpfile_path, processed_paths['of'])
            else:
                logging.debug("Output file: {}".format(processed_paths['of']))
                with open(processed_paths['of'], 'wb', buffering=CHUNK_SIZE) as out_file:
                    if args.num_chunks <= 0:
                        out_file.write(context.decrypt_file())
                    elif args.num_chunks == 1:
                        for chunk in context._yield_chunk():
                            out_file.write(chunk)
                    else:
                        for chunks in context._yield_multiple_chunks(args.num_chunks):
                            out_file.write(chunks)

        except FileNotFoundError as e:
            logging.error("File {} not found, skipping decryption of {}.".format(
                    e.filename, enc_file))
            os.remove(processed_paths['of'])
        except PermissionError as e:
            logging.error("File {} is not readable, skipping decryption of {}.".format(
                    e.filename, enc_file))
            os.remove(processed_paths['of'])
        except NotEncryptedError as e:
            logging.error("File {} does not seem to be encrypted correctly, skipping decryption of {}.".format(
                    e.filename, enc_file))
            os.remove(processed_paths['of'])


if __name__ == '__main__':
    main()
