import base64
import hashlib
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


def sign_RSA(message):

    with open('private.pem', 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    f = Fernet(get_fernet_key_from_password(b'signature'))
    signature = f.encrypt(signature).decode('utf-8')
    return signature

def decode_RSA(message, key_path):
    message = bytes(message)
    with open(key_path, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())

    ciphertext = private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def get_fernet_key_from_password(passcode: bytes) -> bytes:
    assert isinstance(passcode, bytes)
    hlib = hashlib.md5()
    hlib.update(passcode)
    return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))

def send_message(socket, message, counter, encrypt=False, key_path='', symmetric=False, sym_key=''):
    if encrypt and not symmetric:
        message = encrypt_with_public_key(message, key_path)
    else:
        f = Fernet(sym_key)
        message = f.encrypt(bytes(message.encode('utf-8')))

    header = f"{len(message):<{HEADER_LENGTH}}{int(time.time())}{counter%10}".encode('utf-8')

    socket.send(header + message)


def get_fernet_key_from_password(passcode: bytes) -> bytes:
    assert isinstance(passcode, bytes)
    hlib = hashlib.md5()
    hlib.update(passcode)
    return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))