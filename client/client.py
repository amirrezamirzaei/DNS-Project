import json
import socket
import _thread
import hashlib
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from termcolor import colored
from cryptography.fernet import Fernet
from shared_utils import IP_SERVER, PORT_SERVER, receive_message, send_message, get_fernet_key_from_password

LISTEN = True
SYMMETRIC_KEY = None
PUBLIC_KEY_SERVER = '../public.pem'
USERNAME = ''
CLIENT_KEYS = {}


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
                    if sender in CLIENT_KEYS:
                        shared_key = CLIENT_KEYS[sender]
                        fkey = get_fernet_key_from_password(shared_key)
                        f = Fernet(fkey)
                        pm = f.decrypt(pm.encode('utf-8')).decode('utf-8')
                        print(colored(f'new message from {sender}:', 'yellow'), colored(pm, 'magenta'))
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
    CLIENT_KEYS[peer] = generated_key
    print(colored(f'exchanging key with {peer} complete.', 'cyan'))


def send_message_to_client(client_socket, receiver):
    print('enter message:')
    pm = input(colored(f'{USERNAME}>', 'yellow'))
    # encrypt with shared key
    shared_key = CLIENT_KEYS[receiver]
    fkey = get_fernet_key_from_password(shared_key)
    f = Fernet(fkey)
    pm = f.encrypt(bytes(pm.encode('utf-8'))).decode('utf-8')
    message = {'api': 'send_to_client', 'sender': USERNAME, 'receiver': receiver, 'pm': pm}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

    client_socket.setblocking(True)
    server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)

    if server_response == 'username does not exist.' or server_response == 'you are not logged in.' \
            or server_response == 'user not online.':
        print(colored(server_response, 'red'))
        return
    if server_response == 'sent.':
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

    if receiver in CLIENT_KEYS:  # already have key set between two client
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


def main():
    global LISTEN
    global SYMMETRIC_KEY

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

    CLI = colored('1-create account\n2-login\n3-logout\n4-show online users\n5-send message\n', 'blue')

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


if __name__ == "__main__":
    main()
