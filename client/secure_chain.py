import cryptography
from cryptography.fernet import Fernet
from termcolor import colored

from utils import get_fernet_key_from_password


class SecureChain:
    def __init__(self):
        self.session_keys = {}
        self.messages = []  # (message, is_encrypted_with_session_key, incoming, peer_username, group_name)
        self.default_pass = ''

    def add_session_key(self, peer_username, key, master_pass):
        if type(key) == bytes:
            key = key.decode('utf-8')

        saved_key = bytes(key.encode('utf-8'))

        master_key = get_fernet_key_from_password(master_pass.encode('utf-8'))
        f = Fernet(master_key)
        saved_key = f.encrypt(saved_key)
        self.session_keys[peer_username] = saved_key

    def get_session_key(self, peer_username, master_pass):
        encrypted_session_key = self.session_keys.get(peer_username, None)
        if encrypted_session_key is None:
            return None
        for password in [master_pass, self.default_pass]:
            master_key = get_fernet_key_from_password(password.encode('utf-8'))
            f = Fernet(master_key)
            try:
                session_key = f.decrypt(encrypted_session_key).decode('utf-8')
                return bytes(session_key.encode('utf-8'))

            except cryptography.fernet.InvalidToken:
                continue
        print(colored('wrong master pass', 'red'))
        return None

    def get_peers(self):
        return self.session_keys.keys()

    def remove_session_key(self, peer_username):
        if peer_username in self.session_keys:
            self.session_keys[peer_username] = None

    def have_session_with(self, peer_username):
        key = self.session_keys.get(peer_username, None)
        return key is not None

    def set_default_pass(self, password):
        self.default_pass = password

    def change_password(self, password, old_pass):
        keys = {}
        for peer_username in self.session_keys:
            key = self.get_session_key(peer_username, old_pass)
            if not key:
                print(colored('incorrect password. aborting.', 'red'))
                return
            keys[peer_username] = key
        self.session_keys = {}
        for peer_username, key in keys.items():
            self.add_session_key(peer_username, key, password)

    def add_message(self, message, is_encrypted_with_session_key, incoming, peer_username, group_name='', forward_to_all=False):
        # encode message
        if type(message) == str:
            message = message.encode('utf-8')
        key = get_fernet_key_from_password(self.default_pass.encode('utf-8'))
        f = Fernet(key)
        message = f.encrypt(message)

        self.messages.append(
            (message, is_encrypted_with_session_key, incoming, peer_username, group_name, forward_to_all))

    def show_all_messages(self, message_old_password, message_new_password, keychain_pass):
        new_encoding_messages = []
        for i in range(len(self.messages)):
            message, is_encrypted_with_session_key, incoming, peer_username, group_name, forward_to_all = self.messages[i]
            flag = False
            for password in [message_old_password, self.default_pass]:
                f = Fernet(get_fernet_key_from_password(password.encode('utf-8')))
                try:
                    message = f.decrypt(message)
                    flag = True
                except cryptography.fernet.InvalidToken:
                    continue
            if not flag:
                print(colored('incorrect old password. aborting.', 'red'))
                return

            if is_encrypted_with_session_key:
                session_key = self.get_session_key(peer_username, keychain_pass)
                if session_key is None:
                    print(colored('dont have message session key. skipping.', 'red'))
                    continue

                try:
                    f = Fernet(session_key)
                    message = f.decrypt(message)
                except cryptography.fernet.InvalidToken:
                    print(colored('invalid session key. skipping.', 'red'))
                    continue

            if incoming and not group_name:
                print(colored(f'received from {peer_username}:', 'yellow'),
                      colored(f'{message.decode("utf-8")}', 'magenta'))
            elif incoming and group_name:
                print(colored(f'{group_name}:', 'red'), colored(f'received from {peer_username}:', 'yellow'),
                      colored(f'{message.decode("utf-8")}', 'magenta'))
            elif not incoming and not group_name:
                print(colored(f'sent to {peer_username}:', 'yellow'), colored(f'{message.decode("utf-8")}', 'magenta'))
            else:
                print(colored(f'{group_name}:', 'red'), colored(f'sent to {peer_username}:', 'yellow'),
                      colored(f'{message.decode("utf-8")}', 'magenta'))

            f = Fernet(get_fernet_key_from_password(message_new_password.encode('utf-8')))
            message = f.encrypt(message)

            new_encoding_messages.append((message, False, incoming, peer_username, group_name, False))
        self.messages = new_encoding_messages

# test
# k = KeyChain()
# k.default_pass = 'password'
# k.add_session_key('user1', 'sessionkey', 'password')
# k.add_session_key('user2', 'sessionkey', 'password')
