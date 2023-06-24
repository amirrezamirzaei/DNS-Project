import socket
import _thread

from shared_utils import IP_SERVER, PORT_SERVER, receive_message, send_message

LISTEN = True


def listen_for_message(recv_socket):
    while True:
        if LISTEN:
            recv_socket.setblocking(0)
            message = receive_message(recv_socket)
            if message:
                print(message)


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

    CLI = '1-create account\n2-sign in\n'

    while True:
        command = int(input(CLI))

        if command == 1:  # create account
            print(1)
            send_message(client_socket, 'salam hale shoma chetore?')

        elif command == 2:  # sign up
            print('accc')
            print(2)
            send_message(client_socket, 'kheili ham aali')


if __name__ == "__main__":
    main()
