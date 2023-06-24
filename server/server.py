import socket
from _thread import start_new_thread

from shared_utils import receive_message, IP_SERVER, PORT_SERVER, send_message

clients = []


def handle_client(client_socket, client_address):
    clients.append(client_socket)
    print(clients)
    while True:
        message = receive_message(client_socket)
        if message:
            print(message)
            send_message(client_socket, 'dge inja peygham nade.')


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
