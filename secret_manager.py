#!/usr/bin/env python
import argparse
import base64
import json
import logging
import sys
from getpass import getpass

import cryptography.fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__version__ = "0.1"
DEFAULT_SECRET_FILE = './secret'


class SecretManager:
    def __init__(self, master_key, secret_file=DEFAULT_SECRET_FILE):
        if isinstance(master_key, str):
            master_key = master_key.encode()
        if not isinstance(master_key, bytes):
            raise TypeError('master key should be of bytes type')
        self.master_key = master_key
        self.secret_file = secret_file
        try:
            open(self.secret_file, 'rb').close()
            self.empty = False
        except FileNotFoundError:
            open(self.secret_file, 'wb').close()
            self.empty = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def _decrypt_secrets(self, encrypted_secrets):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        f = Fernet(key)
        try:
            return json.loads(f.decrypt(encrypted_secrets))
        except cryptography.fernet.InvalidToken:
            logging.error('error in decryption')
            return None

    def _encrypt_secrets(self, secrets):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        f = Fernet(key)
        return f.encrypt(secrets)

    def add_secret(self, secret_name):
        with open(self.secret_file, 'rb') as fb:
            encrypted_secrets = fb.read()

        if encrypted_secrets:
            secrets = self._decrypt_secrets(encrypted_secrets)
            if secrets is None:
                return
        else:
            secrets = {}

        if secret_name in secrets:
            logging.error('this secret is already present')
            return False
        else:
            secrets[secret_name] = getpass('secret value: ')
            encrypted_secrets = self._encrypt_secrets(json.dumps(secrets).encode())
            with open(self.secret_file, 'wb') as fb:
                fb.write(encrypted_secrets)
            self.empty = False
            logging.info('secret succesfully added')

    def del_secret(self, secret_name):
        if self.empty:
            logging.info('empty file')
            return False

        if self.get_secret(secret_name):
            with open(self.secret_file, 'rb') as fb:
                encrypted_secrets = fb.read()
            secrets = self._decrypt_secrets(encrypted_secrets)
            del secrets[secret_name]
            encrypted_secrets = self._encrypt_secrets(json.dumps(secrets).encode())
            with open(self.secret_file, 'wb') as fb:
                fb.write(encrypted_secrets)
            logging.info('secret successfully deleted')
        else:
            return False

    def get_secret(self, secret_name):
        if self.empty:
            logging.info('empty file')
            return False

        with open(self.secret_file, 'rb') as fb:
            encrypted_secrets = fb.read()
        secrets = self._decrypt_secrets(encrypted_secrets)
        if secret_name in secrets:
            return secrets[secret_name]
        else:
            logging.error('this secret is not present')
            return False

    def getall(self):
        if self.empty:
            logging.info('empty file')
            return
        with open(self.secret_file, 'rb') as fb:
            encrypted_secrets = fb.read()
        if encrypted_secrets:
            secrets = self._decrypt_secrets(encrypted_secrets)
            if secrets is not None:
                return list(secrets.keys())
            else:
                return None


def parse_arguments():
    parser = argparse.ArgumentParser('Secrets manager')

    action_subparsers = parser.add_subparsers(title='Action', dest='action')

    add_sp = action_subparsers.add_parser('add')
    get_sp = action_subparsers.add_parser('get')
    del_sp = action_subparsers.add_parser('del')
    getall_sp = action_subparsers.add_parser('getall')

    parser.add_argument('-n', '--secret_name', help='Name of the secret', required=True if not 'getall' in sys.argv else False)
    parser.add_argument('-f', '--secret_file', default=DEFAULT_SECRET_FILE, help=f'default is {DEFAULT_SECRET_FILE}')
    return parser.parse_args()


def main():
    with SecretManager(getpass('master key: '), args.secret_file) as sm:
        if args.action == 'add':
            sm.add_secret(args.secret_name)
        elif args.action == 'get':
            secret = sm.get_secret(args.secret_name)
            if secret:
                print(secret)
        elif args.action == 'getall':
            all_names = sm.getall()
            if all_names:
                print(", ".join(all_names))
        else:
            sm.del_secret(args.secret_name)


if __name__ == '__main__':
    args = parse_arguments()
    main()
