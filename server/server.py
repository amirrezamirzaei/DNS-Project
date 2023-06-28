import socket
from _thread import start_new_thread
import json

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
    print(clients)
    if message['username'] not in clients:
        send_message(client_socket, 'username does not exist.', encrypt=True, symmetric=True, sym_key=sym_key)
    elif clients[message['username']]['password'] != message['password']:
        send_message(client_socket, 'password does not match username.', encrypt=True, symmetric=True, sym_key=sym_key)
    else:
        send_message(client_socket, 'login successful.', encrypt=True, symmetric=True, sym_key=sym_key)
        clients[message['username']]['socket'] = client_socket


def handle_logout(message, client_socket, sym_key):
    if message['username'] in clients and clients[message['username']]['socket'] == client_socket:
        clients[message['username']]['socket'] = None


def handle_client(client_socket, client_address):
    global clients
    sym_key = None

    # get symmetric key from client
    client_socket.setblocking(True)
    sym_key = receive_message(client_socket, decrypt=True, key_path='private.pem')
    print(sym_key)

    while True:
        client_socket.setblocking(True)
        message = receive_message(client_socket, decrypt=True, symmetric=True, sym_key=sym_key)
        if message:
            print(message)
            message = json.loads(message.replace("'", '"'))

            if message['api'] == 'signup_username':
                handle_signup(message, client_socket, sym_key)
            elif message['api'] == 'assign_password':
                handle_assign_password(message, client_socket, sym_key)
            elif message['api'] == 'login':
                handle_login(message, client_socket, sym_key)
            elif message['api'] == 'logout':
                handle_logout(message, client_socket, sym_key)


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
