import json
import socket
import _thread
import hashlib
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from termcolor import colored
from cryptography.fernet import Fernet

from emojify import text_to_emoji
from secure_chain import SecureChain
from utils import IP_SERVER, HEADER_LENGTH, PORT_SERVER, get_fernet_key_from_password, encrypt_with_public_key, \
    decode_RSA

LISTEN = True
SYMMETRIC_KEY = None
PUBLIC_KEY_SERVER = '../public.pem'
USERNAME = ''
CLIENT_SECURE_CHAIN = SecureChain()
DEFAULT_SECURE_CHAIN_PASS = ''
REPLAY_WINDOW = [None for i in range(10)]
COUNTER = 0


def listen_for_message(recv_socket):
    while True:
        if LISTEN:
            recv_socket.setblocking(False)
            message = receive_message(recv_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY, jsonify=True)
            if message:
                if message['api'] == 'exchange1':
                    exchange_key(recv_socket, message)
                elif message['api'] == 'new_message_from_client':
                    pm = message['pm']
                    sender = message['sender']
                    if CLIENT_SECURE_CHAIN.have_session_with(sender):
                        print(colored(f'new message from {sender}:', 'yellow'), colored(pm, 'magenta'))
                        CLIENT_SECURE_CHAIN.add_message(pm, True, True, sender)
                    else:
                        print(colored('message received from client without shared key', 'red'))
            else:
                time.sleep(1)


def exchange_key(client_socket, server_response):
    # server response will be public diffie hellman parameters
    if type(server_response) == str:
        server_response = json.loads(server_response.replace("'", '"'))
    peer = server_response['username']
    print(colored(f'exchanging key with {peer}', 'cyan'))
    p, g = server_response['p'], server_response['g']
    params_numbers = dh.DHParameterNumbers(p, g)
    parameters = params_numbers.parameters(default_backend())
    private_key = parameters.generate_private_key()
    peer_public_key = private_key.public_key()

    message = {'api': 'key_exchange_with_another_client_p2', 'sender': USERNAME,
               'receiver': peer, 'y': peer_public_key.public_numbers().y}

    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)
    client_socket.setblocking(True)
    message = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY, jsonify=True)
    p = dh.DHPublicNumbers(message['y'], params_numbers)
    generated_key = get_fernet_key_from_password(private_key.exchange(p.public_key(default_backend())))
    CLIENT_SECURE_CHAIN.add_session_key(peer, generated_key, CLIENT_SECURE_CHAIN.default_pass)
    print(colored(f'exchanging key with {peer} complete.', 'cyan'))


def send_message_to_client(client_socket, receiver):
    print('enter message:')
    pm = input(colored(f'{USERNAME}>', 'yellow'))
    # encrypt with shared key
    print('enter key chain password:')
    password = input(colored(f'{USERNAME}>', 'yellow'))
    shared_key = CLIENT_SECURE_CHAIN.get_session_key(receiver, password)
    if shared_key is None:
        return
    f = Fernet(shared_key)
    pm_after_encryption = f.encrypt(bytes(pm.encode('utf-8'))).decode('utf-8')
    message = {'api': 'send_to_client', 'sender': USERNAME, 'receiver': receiver, 'pm': pm_after_encryption}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

    client_socket.setblocking(True)
    server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)

    if server_response == 'username does not exist.' or server_response == 'you are not logged in.' \
            or server_response == 'user not online.':
        print(colored(server_response, 'red'))
        return
    if server_response == 'sent.':
        CLIENT_SECURE_CHAIN.add_message(pm, False, False, receiver)
        print(colored(server_response, 'green'))
        return


def handle_signup(client_socket):
    username = input('enter your desired username:')
    message = {'api': 'signup_username', 'username': username}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

    client_socket.setblocking(True)
    server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)

    if server_response == 'username already exist.':
        print(colored('a user with this username already exists.', 'red'))
        return
    elif server_response == 'username does not exist.':
        password = input('please enter a password:')
        hash = hashlib.sha256()
        hash.update(bytes(password.encode('utf-8')))
        password = hash.hexdigest()

        message = {'api': 'assign_password', 'username': username, 'password': password}
        send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

        server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)
        if server_response == 'signup successful.':
            print(colored('user successfully registered.', 'green'))
        elif server_response == 'username does not exist.':
            print(colored('a user with this username already exists.', 'red'))


def handle_login(client_socket):
    global LISTEN
    global USERNAME

    username = input('enter your username:')
    password = input('enter your password:')
    hash = hashlib.sha256()
    hash.update(bytes(password.encode('utf-8')))
    password = hash.hexdigest()
    message = {'api': 'login', 'username': username, 'password': password}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

    client_socket.setblocking(True)
    server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)

    if server_response == 'username does not exist.' or server_response == 'password does not match username.' \
            or server_response == 'user is already logged in.':
        print(colored(server_response, 'red'))
    elif server_response == 'login successful.':
        print(colored(f'{server_response} Welcome', 'green'), colored(f'{username}!', 'yellow'))
        USERNAME = username

        print('enter secure chain default password:')
        password = input(colored(f'{USERNAME}>', 'yellow'))
        CLIENT_SECURE_CHAIN.set_default_pass(password)


def handle_logout(client_socket):
    global USERNAME
    if len(USERNAME) == 0:
        print(colored('you are not signed in!', 'red'))
    message = {'api': 'logout', 'username': USERNAME}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

    print(colored('goodbye', 'green'), colored(f'{USERNAME}!', 'yellow'))
    USERNAME = ''


def handle_show_online_users(client_socket):
    message = {'api': 'show_online_users'}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)
    client_socket.setblocking(True)
    server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)
    print(colored(server_response, 'magenta'))


def handle_send_message(client_socket):
    print('enter username of the receiver:')
    receiver = input(colored(f'{USERNAME}>', 'yellow'))
    if CLIENT_SECURE_CHAIN.have_session_with(receiver):  # already have key set between two client
        send_message_to_client(client_socket, receiver)

    else:  # initiate key exchange protocol
        message = {'api': 'key_exchange_with_another_client_p1', 'sender': USERNAME, 'receiver': receiver}
        send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

        client_socket.setblocking(True)
        server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)

        if server_response == 'username does not exist.' or server_response == 'you are not logged in.' \
                or server_response == 'user not online.':
            print(colored(server_response, 'red'))
            return

        exchange_key(client_socket, server_response)

        send_message_to_client(client_socket, receiver)


def handle_change_keychain_pass():
    print('enter key chain old password:')
    old_pass = input(colored(f'{USERNAME}>', 'yellow'))
    print('enter new password for your key chain:')
    new_pass = input(colored(f'{USERNAME}>', 'yellow'))
    CLIENT_SECURE_CHAIN.change_password(new_pass, old_pass)


def handle_message_history(client_socket):
    print('enter key chain password:')
    keychain_pass = input(colored(f'{USERNAME}>', 'yellow'))
    print('enter message list old password:')
    old_pass = input(colored(f'{USERNAME}>', 'yellow'))
    print('enter new password for your message list:')
    new_pass = input(colored(f'{USERNAME}>', 'yellow'))
    CLIENT_SECURE_CHAIN.show_all_messages(old_pass, new_pass, keychain_pass)


def handle_check_session_integrity():
    print('enter key chain password:')
    keychain_pass = input(colored(f'{USERNAME}>', 'yellow'))
    for peer in CLIENT_SECURE_CHAIN.get_peers():
        key = CLIENT_SECURE_CHAIN.get_session_key(peer, keychain_pass)
        if key:
            print(f'{peer}:{text_to_emoji(key)}')


def main():
    global LISTEN
    global SYMMETRIC_KEY
    global CLIENT_SECURE_CHAIN

    client_socket = socket.socket()
    try:
        client_socket.connect((IP_SERVER, PORT_SERVER))
    except socket.error:
        print('connection refused')
        exit()
    print('connection established.')
    client_socket.setblocking(True)
    # generate symmetric key for server
    SYMMETRIC_KEY = Fernet.generate_key()
    send_message(client_socket, SYMMETRIC_KEY, symmetric=False, encrypt=True, key_path=PUBLIC_KEY_SERVER)

    _thread.start_new_thread(listen_for_message, (client_socket,))

    CLI = colored('1-create account\n'
                  '2-login\n'
                  '3-logout\n'
                  '4-show online users\n'
                  '5-send message\n'
                  '6-message history\n'
                  '7-set keychain password\n'
                  '8-check session integrity\n',
                  'blue')
    # secret dev menu
    # -1 to show keychain
    while True:
        print(CLI)
        try:
            command = int(input(colored(f'{USERNAME}>', 'yellow')))
        except:
            continue

        if command == 1:  # create account
            LISTEN = False
            handle_signup(client_socket)
            LISTEN = True

        elif command == 2:  # sign up
            LISTEN = False
            handle_login(client_socket)
            LISTEN = True
        elif command == 3:
            handle_logout(client_socket)
        elif command == 4:
            LISTEN = False
            handle_show_online_users(client_socket)
            LISTEN = True
        elif command == 5:
            LISTEN = False
            handle_send_message(client_socket)
            LISTEN = True
        elif command == 6:
            LISTEN = False
            handle_message_history(client_socket)
            LISTEN = True
        elif command == 7:
            LISTEN = False
            handle_change_keychain_pass()
            LISTEN = True
        elif command == 8:
            LISTEN = False
            handle_check_session_integrity()
            LISTEN = True
        elif command == -1:
            print(CLIENT_SECURE_CHAIN.session_keys)
        elif command == -2:
            print(CLIENT_SECURE_CHAIN.messages)


def receive_message(socket, print_before_decrypt=False, decrypt=False, key_path='', symmetric=False, sym_key='',
                    jsonify=False):
    global REPLAY_WINDOW
    try:
        message_header = socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False

        message_length = int(message_header.decode('utf-8').strip())
        message = socket.recv(message_length)

        if print_before_decrypt:
            print(message)

        if decrypt and not symmetric:
            message = decode_RSA(message, key_path)
            timestamp = message.decode('utf-8')[-11:-1]
            counter = int(message.decode('utf-8')[-1])
            hash_message = message.decode('utf-8')[-75:-11]
            message = message.decode('utf-8')[0:-75].encode('utf-8')
        else:
            f = Fernet(sym_key)
            message = f.decrypt(message).decode('utf-8')
            timestamp = message[-11:-1]
            counter = int(message[-1])
            hash_message = message[-75:-11]
            message = message[0:-75]

        # check integrity
        hash = hashlib.sha256()
        if type(message) == str:
            hash.update(message.encode('utf-8'))
        else:
            hash.update(message)
        if hash.hexdigest() != hash_message:
            print(colored('Integrity of message error', 'red'))
            return False

        # check replay attack
        if REPLAY_WINDOW[counter] is None or REPLAY_WINDOW[counter] < timestamp:
            REPLAY_WINDOW[counter] = timestamp
        else:
            print(colored('REPLAY ATTACK!', 'red'))
            return False

        if jsonify:
            return json.loads(message.replace("'", '"'))
        else:
            return message
    except:
        return False


def send_message(socket, message, encrypt=False, key_path='', symmetric=False, sym_key=''):
    global COUNTER
    if type(message) == str:
        message = message.encode('utf-8')

    hash = hashlib.sha256()
    hash.update(message)
    message = message + hash.hexdigest().encode('utf-8')  # add hash

    message = message + f'{int(time.time())}{COUNTER % 10}'.encode('utf-8')  # add replay attack checker
    COUNTER += 1

    if encrypt and not symmetric:
        message = encrypt_with_public_key(message, key_path)
    else:
        f = Fernet(sym_key)
        message = f.encrypt(bytes(message))

    header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

    socket.send(header + message)


if __name__ == "__main__":
    main()
