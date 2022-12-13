#! /usr/bin/env python

import json
import socket
import sys
import time
import threading
import select
import traceback
from typing import Any, TypedDict, Literal
from enum import Enum, auto, unique
from utils.cast import cast_to_bytes, cast_to_str
from utils.encryption import decrypt_rsa, deserialize_rsa_public_key, encrypt_rsa, hash, serialize_rsa_public_key, sign, verify

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

SENDING_MESSAGE = "sending_message"
SENDING_PUBLIC_TOKEN = "sending_public_token"
SENDING_SYMMETRIC_KEY = "sending_symmetric_key"

MESSAGE_TYPE = Literal['sending_message', 'sending_public_token', 'sending_symmetric_key']

FORMAT = 'utf-8'


class SocketMessage(TypedDict):
    senderId: str
    senderName: str
    msg_type: str
    msg: str


class Client(threading.Thread):

    id: str = ''
    user_name: str = ''

    public_key: RSAPublicKey | None = None
    private_key: RSAPrivateKey | None = None

    symmetric_key = b''
    fernet: Fernet

    keys: dict[str, RSAPublicKey] = {}
    sock: socket.socket

    def __init__(self):
        time_stamp = time.time()

        self.id = 'client_' + time_stamp.__str__()
        self.generate_keys_rsa()
        super().__init__()

    def generate_keys_rsa(self):
        # gera as chaves do Client e guarda
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def generate_key(self) -> None:
        self.symmetric_key = Fernet.generate_key()
        self.fernet = Fernet(self.symmetric_key)

    def load_keys(self) -> dict[str, RSAPublicKey] | None:
        if (not self.id or not self.private_key or not self.public_key):
            return None

        return {self.id: self.public_key}

    def encrypt_fernet(self, message: str):
        return self.fernet.encrypt(message.encode(FORMAT))

    def decrypt_fernet(self, ciphertext, key):  # privateKey
        try:
            return self.fernet.decrypt(ciphertext, key).decode(FORMAT)
        except:
            return False

    # def serialize_rsa_public_key(self, key: RSAPublicKey):
    #     return key.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo
    #     )

    def connect(self, host: str, port: int) -> None:
        self.sock.connect((host, port))

    def send_to_clients(self, msg: str | bytes, msg_type: MESSAGE_TYPE) -> None:
        # formata as mensagens para a serem enviadas com um cabeçalho próprio
        socket_message: SocketMessage = {
            "senderId": self.id,
            "senderName": self.user_name,
            "msg_type": msg_type,
            "msg": cast_to_str(msg)
        }

        # converte o formato padrão em JSON e bytes para o envio
        self.sock.send(json.dumps(socket_message).encode(FORMAT))

    def run(self):
        # chaves já geradas no init

        if not self.public_key:
            print("public_key is empty")
            return
        if not self.private_key:
            print("private_key is empty")
            return

        # pre-configuração do socket
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
        # Conecta socket com o Servidor já rodando
        self.connect(host, port)
        print("Connected\n")
        # self.user_name = input("Enter the User Name to be Used\n>>")
        self.user_name = "user1"

        time.sleep(1)
        # configura Nova thread
        srv = Server(self)
        srv.daemon = True
        print("Starting service")
        # executa Nova thread para controlar os recebimentos de mensagens
        srv.start()

        # TODO: (Não) talvez, enviar infinitamente até receber q alguém recebeu, para saber se recebeu vai vir pela thread de Server uma mensagem

        # Broadcasting minha chave pública, independente de ter alguém para responder
        self.send_to_clients(serialize_rsa_public_key(
            self.public_key), SENDING_PUBLIC_TOKEN)

        while 1:
            while self.keys.__len__():
                if not self.symmetric_key.__len__():
                    self.generate_key()
                    for id, publicKey in self.keys.items():
                        msg = json.dumps({
                            "to": id,
                            "from": self.id,
                            "publicKey": cast_to_str(serialize_rsa_public_key(self.public_key)),
                            "symmetricKey": cast_to_str(encrypt_rsa(self.symmetric_key, publicKey)),
                            "sign": cast_to_str(sign(self.symmetric_key, self.private_key))
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
            data = msg.encode(FORMAT)
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
                    # recebe mensagem do server
                    s = item.recv(1024)
                    if s != '' and s != b'':
                        chunk: bytes = s
                        print('Received new message')
                        # interpreta a mensagem como json e esparasse q seja do meu tipo SocketMessage
                        sck_msg: SocketMessage = json.loads(
                            chunk.decode(FORMAT))
                        print("message from " + sck_msg["senderName"] + '\n>>')

                        msg_type = sck_msg["msg_type"]

                        if msg_type == SENDING_PUBLIC_TOKEN:
                            # esse cliente esta recebendo a PublicKey de alguém

                            # converter str da mensagem em RSAPublicKey
                            key = deserialize_rsa_public_key(sck_msg["msg"])
                            if key is None:
                                continue

                            # salvando relação RSAPublicKey com o dono
                            self.client.keys[sck_msg["senderId"]] = key

                        elif msg_type == SENDING_SYMMETRIC_KEY:
                            # TODO: convert str em dicionario
                            infos_json: dict[str, Any] = sck_msg["msg"]
                            if not (infos_json.get("to") == self.client.id):
                                continue

                            # verify sign
                            infos_json.get("sign")
                            # load_pem_public_key
                            verify()

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

                        elif msg_type ==  SENDING_MESSAGE:
                            # mensagem normal
                            # TODO: fazer envio de mensagem normal criptografada para geral
                            pass

                except:
                    traceback.print_exc(file=sys.stdout)
                    break


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
