import socket
from _thread import start_new_thread
import json
from shared_utils import receive_message, IP_SERVER, PORT_SERVER, send_message

clients = {'admin': ()}


def handle_signup(message, client_socket, sym_key):
    if message['username'] in clients:
        send_message(client_socket, 'username already exist.', encrypt=True, symmetric=True, sym_key=sym_key)
    else:
        send_message(client_socket, 'username does not exist.', encrypt=True, symmetric=True, sym_key=sym_key)


def handle_assing_password(message, client_socket, sym_key):
    if message['username'] in clients:
        send_message(client_socket, 'username already exist.', encrypt=True, symmetric=True, sym_key=sym_key)
        return
    username = message['username']
    password = message['password']

    clients[username] = (None, password)

    send_message(client_socket, 'signup successful.', encrypt=True, symmetric=True, sym_key=sym_key)


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
                handle_assing_password(message, client_socket, sym_key)


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
