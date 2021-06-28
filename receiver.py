import base64
import socket
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime


def create_public_key(p, s):
    """
    creates public key with password and salt
    :param p: password
    :param s: salt
    :return: public key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=s,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(p))


if __name__ == '__main__':

    if len(sys.argv) != 4:
        print("Wrong amount of arguments\nPlease enter the password, salt and port number!")
        exit(1)

    port = int(sys.argv[3])

    # create socket and listen to port entered wirth the arguments
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.bind(("", int(port)))
    socket.listen()

    key = create_public_key(p=bytes(sys.argv[1], encoding='utf-8'), s=bytes(sys.argv[2], encoding='utf-8'))
    f = Fernet(key)

    """
    create the socket and receiving messages
    """
    while True:
        conn, addr = socket.accept()

        data = conn.recv(8192)
        decrypted_message = f.decrypt(data).decode('utf-8')

        # enter the time and print the message with the time
        current_time = datetime.now().strftime("%H:%M:%S")
        print(decrypted_message + " " + current_time)
