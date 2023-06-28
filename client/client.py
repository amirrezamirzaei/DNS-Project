import socket
import _thread
import json
from termcolor import colored

from shared_utils import IP_SERVER, PORT_SERVER, receive_message, send_message

LISTEN = True


def listen_for_message(recv_socket):
    while True:
        if LISTEN:
            recv_socket.setblocking(False)
            message = receive_message(recv_socket)
            if message:
                print(message)


def handle_signup(client_socket):
    global LISTEN
    username = input('enter your desired username:')
    message = {'api': 'signup_username', 'username': username}
    send_message(client_socket, str(message))

    client_socket.setblocking(True)
    server_response = receive_message(client_socket)

    print(server_response)
    if server_response == 'username already exist.':
        print(colored('a user with this username already exists.', 'red'))
        return
    elif server_response == 'username does not exist.':
        password = input('please enter a password:')
        message = {'api': 'assign_password', 'username': username, 'password': password}
        send_message(client_socket, str(message))

        server_response = receive_message(client_socket)
        if server_response == 'signup successful.':
            print(colored('user successfully registered.', 'green'))
        elif server_response == 'username does not exist.':
            print(colored('a user with this username already exists.', 'red'))


def main():
    global LISTEN
    client_socket = socket.socket()
    try:
        client_socket.connect((IP_SERVER, PORT_SERVER))
    except socket.error:
        print('connection refused')
        exit()
    print('connection established.')

    _thread.start_new_thread(listen_for_message, (client_socket,))

    CLI = colored('1-create account\n2-sign in\n', 'blue')

    while True:
        command = int(input(CLI))

        if command == 1:  # create account
            LISTEN = False
            handle_signup(client_socket)
            LISTEN = True

        elif command == 2:  # sign up
            print('accc')
            print(2)
            send_message(client_socket, 'kheili ham aali')


if __name__ == "__main__":
    main()
