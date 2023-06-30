import cryptography
from cryptography.fernet import Fernet
from termcolor import colored

from shared_utils import get_fernet_key_from_password


class KeyChain:

    def __init__(self):
        self.session_keys = {}

    def add_session_key(self, peer_username, key, master_pass):
        if type(key) == bytes:
            key = key.decode('utf-8')

        saved_key = f'key:{key}'
        saved_key = bytes(saved_key.encode('utf-8'))

        master_key = get_fernet_key_from_password(master_pass.encode('utf-8'))
        f = Fernet(master_key)
        saved_key = f.encrypt(saved_key)
        self.session_keys[peer_username] = saved_key

    def get_session_key(self, peer_username, master_pass):
        encrypted_session_key = self.session_keys.get(peer_username, None)
        if encrypted_session_key:
            master_key = get_fernet_key_from_password(master_pass.encode('utf-8'))
            f = Fernet(master_key)
            try:
                session_key = f.decrypt(encrypted_session_key).decode('utf-8')
                if session_key.startswith('key:'):
                    return bytes(session_key[4:].encode('utf-8'))
                else:
                    print(colored('wrong master pass', 'red'))
                    return None
            except cryptography.fernet.InvalidToken:
                print(colored('wrong master pass', 'red'))
                return None

        else:
            return None

    def remove_session_key(self, peer_username):
        if peer_username in self.session_keys:
            self.session_keys[peer_username] = None

# test
# k = KeyChain()
# k.add_session_key('user1', 'sessionkey', 'supersecretmasterkey')
# print(k.get_session_key('user1', 'supersecretmasterkey'))
# print(k.get_session_key('user1', 'pass'))
