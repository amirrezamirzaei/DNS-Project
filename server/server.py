import socket
from _thread import start_new_thread
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from shared_utils import receive_message, IP_SERVER, PORT_SERVER, send_message

clients = {}


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

def handle_client(client_socket, client_address):
    global clients

    # get symmetric key from client
    client_socket.setblocking(True)
    sym_key = receive_message(client_socket, print_before_decrypt=True, decrypt=True, key_path='private.pem')
    print(sym_key)

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
