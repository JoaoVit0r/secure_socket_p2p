#! /usr/bin/env python

import json
import socket
import sys
import time
import threading
import select
import traceback
from typing import Any, TypedDict
from enum import Enum, auto, unique

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

SENDING_PUBLIC_TOKEN = "sending_public_token"
SENDING_SYMMETRIC_KEY = "sending_symmetric_key"

class SocketMessage(TypedDict):
    name: str
    first_letter: str


class Client(threading.Thread):

    id = ''
    user_name = ''

    public_key: RSAPublicKey | None = None

    symmetric_key = b''
    fernet: Fernet

    keys: dict[str, RSAPublicKey] = {}
    sock: socket

    def __init__(self):
        time_stamp = time.time()

        self.id = 'client_' + time_stamp.__str__()
        self.generate_keys_rsa()
        super().__init__()

    def generate_keys_rsa(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def generate_key(self):
        self.symmetric_key = Fernet.generate_key()
        self.fernet = Fernet(self.symmetric_key)

    def load_keys(self):
        if (not self.id or not self.private_key or not self.public_key):
            return None

        return {self.id: self.public_key}

    def encrypt_rsa(self, message: str, key: RSAPublicKey):
        if key is None:
            return None
        return key.encrypt(message.encode())

    def decrypt_rsa(self, ciphertext, key):  # privateKey
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except:
            return False

    def sign(self, message: str, key: RSAPrivateKey):
        if key is None:
            return None
        return key.sign(message.encode(), algorithm=hashes.SHA256())

    def verify(self, message: bytes, signature: bytes, key: RSAPublicKey):  # publicKey
        try:
            key.verify(
                signature,
                message,
                algorithm=hashes.SHA256()
            )
            return True
        except:
            return False

    def hash(self, content: bytes):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(content)
        return digest.finalize()

    def encrypt_fernet(self, message: str):
        return self.fernet.encrypt(message.encode('ascii'))

    def decrypt_fernet(self, ciphertext, key):  # privateKey
        try:
            return self.fernet.decrypt(ciphertext, key).decode('ascii')
        except:
            return False

    def serialize_rsa_public_key(self, key: RSAPublicKey):
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def connect(self, host: str, port: int):
        self.sock.connect((host, port))

    def send_to_clients(self, msg: str, msg_type: str):
        socket_message: SocketMessage = {
            "senderId": self.id,
            "senderName": self.user_name,
            "msg_type": msg_type,
            "msg": msg
        }

        self.sock.send(json.dumps(socket_message).encode())

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            # host = input("Enter the server IP \n>>")
            # port = int(input("Enter the server Destination Port\n>>"))
            host = '0.0.0.0'
            port = 5535
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        self.connect(host, port)
        print("Connected\n")
        # self.user_name = input("Enter the User Name to be Used\n>>")
        self.user_name = "user1"

        time.sleep(1)
        srv = Server(self)
        srv.daemon = True
        print("Starting service")
        srv.start()

        self.send_to_clients(str(self.serialize_rsa_public_key(
            self.public_key)), str(SENDING_PUBLIC_TOKEN))

        while 1:
            while self.keys.__len__():
                if not self.symmetric_key.__len__():
                    self.generate_key()
                    for id, publicKey in self.keys.items():
                        msg = json.dumps({
                            "to": id,
                            "from": self.id,
                            "publicKey": self.serialize_rsa_public_key(self.public_key),
                            "symmetricKey": self.encrypt_rsa(self.symmetric_key, publicKey),
                            "sign": self.sign(self.symmetric_key, self.private_key)
                        })
                        self.send_to_clients(
                            msg, SENDING_SYMMETRIC_KEY)
                    continue

            if not self.symmetric_key.__len__():
                continue
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = self.user_name + ': ' + msg
            data = msg.encode()
            self.send_to_clients(data, SENDING_SYMMETRIC_KEY)
        return (1)


class Server(threading.Thread):
    client: Client

    def __init__(self, client: Client):
        super().__init__()
        self.receive = client.sock
        self.client = client

    def run(self):
        lis = []
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        chunk = s
                        print('Received new message')
                        sck_msg: SocketMessage = json.loads(chunk.decode())
                        print("message from " + sck_msg["senderName"] + '\n>>')

                        msg_type = sck_msg.msg_type

                        if msg_type is SENDING_PUBLIC_TOKEN:
                            self.client.keys[sck_msg["senderId"]
                                             ] = sck_msg.get("msg")

                        elif msg_type == SENDING_SYMMETRIC_KEY:
                            infos_json: dict[str, Any] = sck_msg.get("msg")
                            if not (infos_json.get("to") == self.client.id):
                                continue

                            # verify sign
                            infos_json.get("sign")
                            # load_pem_public_key
                            self.client.verify()

                            # save symmetric key

                            self.client.keys[sck_msg["from"]
                                             ] = sck_msg.get("publicKey")

                            # {
                            #     "to": id,
                            #     "from": self.id,
                            #     "publicKey": self.public_key,
                            #     "symmetricKey": self.encrypt_rsa(self.symmetric_key, publicKey),
                            #     "sign": self.sign(self.symmetric_key, self.private_key)
                            # }
                            pass

                except:
                    traceback.print_exc(file=sys.stdout)
                    break


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
