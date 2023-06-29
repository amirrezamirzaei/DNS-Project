import json
import socket
import _thread
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from termcolor import colored
from cryptography.fernet import Fernet
from shared_utils import IP_SERVER, PORT_SERVER, receive_message, send_message

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
                print(message)
                if message['api'] == 'exchange1':
                    p, g = message['p'], message['g']
                    peer_username = message['username']
                    print(f'exchanging key with {peer_username}')
                    params_numbers = dh.DHParameterNumbers(p, g)
                    parameters = params_numbers.parameters(default_backend())
                    private_key = parameters.generate_private_key()
                    peer_public_key = private_key.public_key()

                    message = {'api': 'key_exchange_with_another_client_p2', 'sender': USERNAME,
                               'receiver': peer_username, 'y': peer_public_key.public_numbers().y}
                    send_message(recv_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

                    recv_socket.setblocking(True)
                    message = receive_message(recv_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)
                    message = json.loads(message.replace("'", '"'))
                    print('joj', message)

                    p = dh.DHPublicNumbers(message['y'], params_numbers)
                    print('khar shreck',private_key.exchange(p.public_key(default_backend())))


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

    if server_response == 'username does not exist.' or server_response == 'password does not match username.':
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

    message = {'api': 'key_exchange_with_another_client_p1', 'sender': USERNAME, 'receiver': receiver}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)

    client_socket.setblocking(True)
    server_response = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY)

    if server_response == 'username does not exist.' or server_response == 'you are not logged in.' \
            or server_response == 'user not online.':
        print(colored(server_response, 'red'))
        return

    # server response will be public diffie hellman parameters
    server_response = json.loads(server_response.replace("'", '"'))

    p, g = server_response['p'], server_response['g']
    params_numbers = dh.DHParameterNumbers(p, g)
    parameters = params_numbers.parameters(default_backend())
    private_key = parameters.generate_private_key()
    peer_public_key = private_key.public_key()

    message = {'api': 'key_exchange_with_another_client_p2', 'sender': USERNAME,
               'receiver': receiver, 'y': peer_public_key.public_numbers().y}
    send_message(client_socket, str(message), encrypt=True, sym_key=SYMMETRIC_KEY, symmetric=True)
    client_socket.setblocking(True)
    message = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=SYMMETRIC_KEY, jsonify=True)
    p = dh.DHPublicNumbers(message['y'], params_numbers)
    print('khar shreck', private_key.exchange(p.public_key(default_backend())))


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
        command = int(input(colored(f'{USERNAME}>', 'yellow')))

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
