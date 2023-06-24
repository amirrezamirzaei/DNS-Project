HEADER_LENGTH = 10
IP_SERVER = "127.0.0.1"
PORT_SERVER = 1234


def receive_message(socket):
    try:
        message_header = socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode('utf-8').strip())
        return socket.recv(message_length)
    except:
        return False


def send_message(socket, message):
    message = message.encode('utf-8')
    header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
    socket.send(header + message)


def encode_RSA(path_key, message):
    pass


def decode_RSA(path_key, message):
    pass
