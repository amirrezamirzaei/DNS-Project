import hashlib
import socket
import time
from _thread import start_new_thread
import json

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from termcolor import colored

from utils import IP_SERVER, HEADER_LENGTH, PORT_SERVER, get_fernet_key_from_password, encrypt_with_public_key, \
    decode_RSA

clients = {}  # user : pass, socket, symkey
client_specific_info = {}  # socket : replay attack manager
group_info = {}


def handle_signup(message, client_socket, sym_key):
    if message['username'] in clients:
        send_message(client_socket, 'username already exist.', encrypt=True, symmetric=True, sym_key=sym_key)
    else:
        send_message(client_socket, 'username does not exist.', encrypt=True, symmetric=True, sym_key=sym_key)


def handle_assign_password(message, client_socket, sym_key):
    if message['username'] in clients:
        send_message(client_socket, 'username already exist.', encrypt=True, symmetric=True, sym_key=sym_key)
        return
    username = message['username']
    password = message['password']

    clients[username] = {'socket': None, 'password': password}

    send_message(client_socket, 'signup successful.', encrypt=True, symmetric=True, sym_key=sym_key)


def handle_login(message, client_socket, sym_key):
    global clients
    if message['username'] not in clients:
        send_message(client_socket, 'username does not exist.', encrypt=True, symmetric=True, sym_key=sym_key)
    elif clients[message['username']]['password'] != message['password']:
        send_message(client_socket, 'password does not match username.', encrypt=True, symmetric=True, sym_key=sym_key)
    elif clients[message['username']]['socket']:
        send_message(client_socket, 'user is already logged in.', encrypt=True, symmetric=True, sym_key=sym_key)
    else:
        send_message(client_socket, 'login successful.', encrypt=True, symmetric=True, sym_key=sym_key)
        clients[message['username']]['socket'] = client_socket
        clients[message['username']]['key'] = sym_key


def handle_logout(message, client_socket, sym_key):
    if message['username'] in clients and clients[message['username']]['socket'] == client_socket:
        clients[message['username']]['socket'] = None
        clients[message['username']]['key'] = None


def handle_show_online_users(message, client_socket, sym_key):
    global clients
    response = ''
    for client, info in clients.items():
        if info['socket']:
            response += client + ' '

    send_message(client_socket, response, encrypt=True, symmetric=True, sym_key=sym_key)


def handle_key_exchange_with_another_client_p1(message, client_socket, sym_key):
    sender = message['sender']
    receiver = message['receiver']
    if sender not in clients or clients[sender]['socket'] != client_socket:
        send_message(client_socket, 'you are not logged in.', encrypt=True, symmetric=True, sym_key=sym_key)
        return
    if receiver not in clients:
        send_message(client_socket, 'username does not exist.', encrypt=True, symmetric=True, sym_key=sym_key)
        return
    elif not clients[receiver]['socket']:
        send_message(client_socket, 'user not online.', encrypt=True, symmetric=True, sym_key=sym_key)
        return

    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    message = {'api': 'exchange1', 'username': receiver, 'p': p, 'g': g}
    send_message(client_socket, str(message), encrypt=True, symmetric=True, sym_key=sym_key)

    message = {'api': 'exchange1', 'username': sender, 'p': p, 'g': g}
    send_message(clients[receiver]['socket'], str(message), encrypt=True, symmetric=True,
                 sym_key=clients[receiver]['key'])


def handle_key_exchange_with_another_client_p2(message, client_socket, sym_key):
    receiver = message['receiver']
    sender = message['sender']
    y = message['y']
    message = {'api': 'exchange2', 'username': sender, 'y': y}
    send_message(clients[receiver]['socket'], str(message), encrypt=True, symmetric=True,
                 sym_key=clients[receiver]['key'])


def handle_send_to_client(message, client_socket, sym_key):
    sender = message['sender']
    receiver = message['receiver']
    pm = message['pm']

    if sender not in clients or clients[sender]['socket'] != client_socket:
        send_message(client_socket, 'you are not logged in.', encrypt=True, symmetric=True, sym_key=sym_key)
        return
    if receiver not in clients:
        send_message(client_socket, 'username does not exist.', encrypt=True, symmetric=True, sym_key=sym_key)
        return
    elif not clients[receiver]['socket']:
        send_message(client_socket, 'user not online.', encrypt=True, symmetric=True, sym_key=sym_key)
        return

    message = {'api': 'new_message_from_client', 'sender': sender, 'pm': pm}
    send_message(clients[receiver]['socket'], str(message), encrypt=True, symmetric=True,
                 sym_key=clients[receiver]['key'])

    send_message(client_socket, 'sent.', encrypt=True, symmetric=True, sym_key=sym_key)


def handle_set_sym_key(message, client_socket, sym_key):
    global clients
    username = message['username']
    new_key = receive_message(client_socket, print_before_decrypt=True, decrypt=True,
                              key_path='private.pem', jsonify=True)['key']

    if not new_key:
        return sym_key

    if username:
        clients[username]['key'] = new_key
    return new_key


def handle_create_group(message, client_socket, sym_key):
    global clients
    global group_info
    admin_username = message['username']
    group_name = message['group_name']
    if admin_username not in clients:
        send_message(client_socket, 'you must login first.', encrypt=True, symmetric=True, sym_key=sym_key)
    elif group_name in group_info:
        send_message(client_socket, 'group with this name already exists.', encrypt=True, symmetric=True,
                     sym_key=sym_key)
    else:
        group_info[group_name] = {'admin': admin_username, 'users': []}
        send_message(client_socket, 'success.', encrypt=True, symmetric=True, sym_key=sym_key)


def handle_group_info(message, client_socket, sym_key):
    global clients
    global group_info
    username = message['username']
    if username not in clients:
        send_message(client_socket, 'you must login first.', encrypt=True, symmetric=True, sym_key=sym_key)
    else:
        result = []
        for group_name, members in group_info.items():
            if members['admin'] == username or username in members['users']:
                result.append({'group_name': group_name, 'admin': members['admin'], 'users': members['users']})
        send_message(client_socket, str(result), encrypt=True, symmetric=True, sym_key=sym_key)


def handle_client(client_socket, client_address):
    global clients
    global client_specific_info

    client_specific_info[client_socket] = [0, [None for i in range(10)]]

    # get symmetric key from client
    client_socket.setblocking(True)
    sym_key = receive_message(client_socket, print_before_decrypt=True, decrypt=True,
                              key_path='private.pem', jsonify=True)['key']

    while True:
        client_socket.setblocking(True)
        message = receive_message(client_socket, print_before_decrypt=True, decrypt=True, symmetric=True,
                                  sym_key=sym_key, jsonify=True)
        if message:
            print(f'received {message}')

            if message['api'] == 'signup_username':
                handle_signup(message, client_socket, sym_key)
            elif message['api'] == 'assign_password':
                handle_assign_password(message, client_socket, sym_key)
            elif message['api'] == 'login':
                handle_login(message, client_socket, sym_key)
            elif message['api'] == 'logout':
                handle_logout(message, client_socket, sym_key)
            elif message['api'] == 'show_online_users':
                handle_show_online_users(message, client_socket, sym_key)
            elif message['api'] == 'key_exchange_with_another_client_p1':
                handle_key_exchange_with_another_client_p1(message, client_socket, sym_key)
            elif message['api'] == 'key_exchange_with_another_client_p2':
                handle_key_exchange_with_another_client_p2(message, client_socket, sym_key)
            elif message['api'] == 'send_to_client':
                handle_send_to_client(message, client_socket, sym_key)
            elif message['api'] == 'set_sym_key_p1':
                sym_key = handle_set_sym_key(message, client_socket, sym_key)
            elif message['api'] == 'create_group':
                handle_create_group(message, client_socket, sym_key)
            elif message['api'] == 'group_info':
                handle_group_info(message, client_socket, sym_key)


def receive_message(socket, print_before_decrypt=False, decrypt=False, key_path='', symmetric=False, sym_key='',
                    jsonify=False):
    global client_specific_info
    try:
        message_header = socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False

        message_length = int(message_header.decode('utf-8').strip())
        message = socket.recv(message_length)

        if print_before_decrypt:
            print('received before decryption:', colored(message, 'yellow'))

        if decrypt and not symmetric:
            message = decode_RSA(message, key_path)
            timestamp = message.decode('utf-8')[-11:-1]
            counter = int(message.decode('utf-8')[-1])
            hash_message = message.decode('utf-8')[-75:-11]
            message = message.decode('utf-8')[0:-75]
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
        if client_specific_info[socket][1][counter] is None or client_specific_info[socket][1][counter] < timestamp:
            client_specific_info[socket][1][counter] = timestamp
        else:
            print(colored('REPLAY ATTACK!', 'red'))
            return False

        print('received after decryption:', colored(message, 'blue'))
        if jsonify:
            return json.loads(message.replace("'", '"'))
        else:
            return message
    except Exception as e:
        print(colored(str(e), 'red'))
        return False


def send_message(socket, message, encrypt=False, key_path='', symmetric=False, sym_key=''):
    global client_specific_info
    counter = client_specific_info[socket][0]
    if type(message) == str:
        message = message.encode('utf-8')

    print('sending:', colored(message, 'green'))

    hash = hashlib.sha256()
    hash.update(message)
    message = message + hash.hexdigest().encode('utf-8')  # add hash

    message = message + f'{int(time.time())}{counter % 10}'.encode('utf-8')  # add replay attack checker
    client_specific_info[socket][0] += 1

    if encrypt and not symmetric:
        message = encrypt_with_public_key(message, key_path)
    else:
        f = Fernet(sym_key)
        message = f.encrypt(bytes(message))

    header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

    socket.send(header + message)


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((IP_SERVER, PORT_SERVER))
    server_socket.listen()

    print(f'Listening for connections on {IP_SERVER}:{PORT_SERVER}...')

    while True:
        client_socket, client_address = server_socket.accept()
        start_new_thread(handle_client, (client_socket, client_address))


if __name__ == "__main__":
    main()
