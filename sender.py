import base64
import socket
import sys

from threading import Thread
from time import sleep
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class ClientPacket:
    """
    packet info class
    """
    def __init__(self, packet, ip, port, sending_round):
        self.packet = packet
        self.ip = ip
        self.port = port
        self.round = sending_round


def read_server_file(file_name):
    """
    read the messages file
    :param file_name: the messages file path
    :return: list of the messages
    """
    to_send_lines = []
    with open(file_name, "r") as f:
        to_send_lines = f.readlines()
    return to_send_lines


def send(packet):
    """
    send function as part of threading process
    each packet sends after its own sleep time
    :param packet: sends packet
    :return:
    """
    sleep((int(packet[0].round) * 60))
    for i in packet:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((i.ip, int(i.port)))
        client.send(i.packet)
        client.close()


def wrap_and_encrypt_packet(pk, address, packet):
    """
    wraps each packet with ip and port.
    :param pk: mix server public key
    :param address: mix server address
    :param packet: the data
    :return: encrypted wrapped packet
    """
    ip = address.split()[0]
    port = address.split()[1]
    sender_message = socket.inet_aton(ip) + int(port).to_bytes(2, 'big') + packet
    return encrypt_with_public_key(message=sender_message, public_key=pk)


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


def load_mix_keys(path, ips_file):
    """
    loads and listing the mix server info
    :param path: the server path to the receiver
    :param ips_file: ips file path
    :return: mix server public keys and servers info
    """
    public_keys = []

    path_params = path.split(",")
    mix_server_ip_file = open(ips_file)
    servers_line = mix_server_ip_file.readlines()

    for mix_index in reversed(path_params):
        key_name = "pk" + mix_index + ".pem"
        with open(key_name, "rb") as key:
            public_key = serialization.load_pem_public_key(key.read(), default_backend())
            public_keys.append(public_key)

    return public_keys, servers_line


def encrypt_with_public_key(message, public_key):
    """
    encrypt data
    :param message: the data to encrypt
    :param public_key: public key to encrypt with
    :return: encrypted data
    """
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def initialize_client_packets(file_name):
    """
    the main function for creating the packets to send to the mix server
    :param file_name: the messages file path
    :return: ready packets to send
    """
    packets = []

    lines = read_server_file(file_name=file_name)

    for line in lines:

        addresses = []

        """
        init the needed data and info in order to send the package
        """
        split_line = line.split()
        data = split_line[0]
        mix_server_path = split_line[1]
        sending_round = split_line[2]
        password = bytes(split_line[3], encoding='utf-8')
        salt = bytes(split_line[4], encoding='utf-8')
        # destination ip and port
        ip = split_line[5]
        port = split_line[6]

        public_key = create_public_key(p=password, s=salt)
        ciphered_data = Fernet(public_key).encrypt(data.encode())

        # concatenate ip + port + c
        sender_message = socket.inet_aton(ip) + int(port).to_bytes(2, 'big') + ciphered_data

        mixer_servers_public_keys, mix_servers = load_mix_keys(path=mix_server_path, ips_file='ips.txt')
        enc_client_packet = encrypt_with_public_key(message=sender_message, public_key=mixer_servers_public_keys[0])

        for mix_index in range(0, len(mix_servers)):
            addresses.append(mix_servers[mix_index].strip())
        for pk_index in range(1, len(mixer_servers_public_keys)):
            enc_client_packet = wrap_and_encrypt_packet(
                pk=mixer_servers_public_keys[pk_index], address=addresses[pk_index - 1], packet=enc_client_packet)

        # finalize the packet with the next mix server to send to
        destination = addresses[-1]
        dst_ip, dst_port = destination.split()[0], destination.split()[1]
        packets.append(
            ClientPacket(packet=enc_client_packet, ip=dst_ip, port=dst_port, sending_round=sending_round)
        )

    return packets


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print("Wrong amount of arguments\nPlease enter the messages file number!")
        exit(1)

    # the messages file index
    X = sys.argv[1]
    client_messages_file_name = "messages" + str(X) + ".txt"

    client_packets = initialize_client_packets(file_name=client_messages_file_name)

    # sort the packets list by round of time
    client_packets.sort(key=lambda x: x.round)

    packet_number = 0
    c_packets = []
    """
    collecting all the same round packets and sends them
    """
    while packet_number < len(client_packets):
        counter = packet_number
        while counter < len(client_packets) and client_packets[counter].round == client_packets[packet_number].round:
            c_packets.append(client_packets[counter])
            counter += 1
        packet_number = counter
        # each one of the packets sends with different thread
        thread = Thread(target=send, args=(c_packets,))
        thread.start()
        thread.join()
        c_packets.clear()
