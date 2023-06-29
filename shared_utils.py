from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.fernet import Fernet

HEADER_LENGTH = 10
IP_SERVER = "127.0.0.1"
PORT_SERVER = 1234


def encrypt_with_public_key(message, key_path):
    message = bytes(message)
    with open(key_path, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = load_pem_public_key(pemlines, default_backend())

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decode_RSA(message, key_path):
    message = bytes(message)
    with open(key_path, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = load_pem_private_key(pemlines, None, default_backend())

    ciphertext = public_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def receive_message(socket, print_before_decrypt=False, decrypt=False, key_path='', symmetric=False, sym_key=''):
    try:
        message_header = socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode('utf-8').strip())
        message = socket.recv(message_length)

        if print_before_decrypt:
            print(message)

        if decrypt and not symmetric:
            message = decode_RSA(message, key_path)
        else:
            f = Fernet(sym_key)
            message = f.decrypt(message).decode('utf-8')

        return message
    except:
        return False


def send_message(socket, message, encrypt=False, key_path='', symmetric=False, sym_key=''):
    if encrypt and not symmetric:
        message = encrypt_with_public_key(message, key_path)
    else:
        f = Fernet(sym_key)
        message = f.encrypt(bytes(message.encode('utf-8')))

    header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

    socket.send(header + message)

