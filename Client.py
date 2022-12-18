#! /usr/bin/env python

import json
import socket
import sys
import time
import threading
import select
import traceback
from base64 import b64encode, b64decode
from typing import Any, TypedDict, Literal
from enum import Enum, auto, unique
from utils.cast import cast_to_str, cast_to_bytes
from utils.encryption import decrypt_rsa, deserialize_rsa_public_key, encrypt_rsa, hash, serialize_rsa_public_key, sign, verify

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SENDING_MESSAGE = "sending_message"
SENDING_PUBLIC_TOKEN = "sending_public_token"
SENDING_SYMMETRIC_KEY = "sending_symmetric_key"

MESSAGE_TYPE = Literal['sending_message',
                       'sending_public_token', 'sending_symmetric_key']

FORMAT = 'utf-8'


class SocketMessage(TypedDict):
    senderId: str
    senderName: str
    msg_type: str
    msg: str


class SocketMessageSymmetricKey(TypedDict):
    to: str
    publicKey: str
    symmetricKey: str
    symmetricKeyTimeStamp: float
    sign: str

# TODO: use this to send message encrypted and you hash


class SocketMessageDefault(TypedDict):
    message: str
    sign: str


class Client(threading.Thread):

    id: str = ''
    user_name: str = ''

    # ja estou criando no init
    # public_key: RSAPublicKey | None = None
    # private_key: RSAPrivateKey | None = None

    symmetric_key_time_stamp = 0.0
    symmetric_key = b''
    fernet: Fernet | None = None

    keys: dict[str, RSAPublicKey] = {}
    sock: socket.socket

    def __init__(self):
        time_stamp = time.time()

        self.id = 'client_' + time_stamp.__str__()
        self.user_name = sys.argv.pop()
        self.generate_keys_rsa()
        super().__init__()

    def generate_keys_rsa(self):
        # gera as chaves do Client e guarda
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def generate_key(self) -> None:
        # gera nova chave simétrica, anotando o horário
        self.symmetric_key_time_stamp = time.time()
        self.symmetric_key = Fernet.generate_key()
        self.fernet = Fernet(self.symmetric_key)

    def update_key(self, symmetric_key: bytes, symmetric_key_time_stamp: float) -> None:
        # armazena nova chave simétrica, anotando o horário
        print("!!! update_key")
        self.symmetric_key_time_stamp = symmetric_key_time_stamp
        self.symmetric_key = symmetric_key
        self.fernet = Fernet(self.symmetric_key)

    def load_keys(self) -> dict[str, RSAPublicKey] | None:
        if (not self.id or not self.private_key or not self.public_key):
            return None

        return {self.id: self.public_key}

    def encrypt_fernet(self, message: str) -> bytes:
        if self.fernet is None:
            return b''
        return self.fernet.encrypt(message.encode(FORMAT))

    def decrypt_fernet(self, cipher_text) -> bytes:
        if self.fernet is None:
            return b''
        try:
            return self.fernet.decrypt(cipher_text)
        except:
            return b''

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

    def payload_to_send_symmetric_key(self, destiny_id: str, destiny_public_key: RSAPublicKey) -> SocketMessageSymmetricKey:
        # gerar o objeto python que será enviado para algum cliente, que precisa da chave síncrona atualizada
        symmetric_key_payload: SocketMessageSymmetricKey = {
            "to": destiny_id,
            "publicKey": cast_to_str(serialize_rsa_public_key(self.public_key)),
            "symmetricKey": cast_to_str(b64encode(encrypt_rsa(self.symmetric_key, destiny_public_key))),
            "symmetricKeyTimeStamp": self.symmetric_key_time_stamp,
            "sign": cast_to_str(b64encode(sign(self.symmetric_key, self.private_key)))
        }
        return symmetric_key_payload

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
        # self.user_name = input("Enter the User Friendly Name to be Used\n>>")
        # self.user_name = "user1"

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
            # while self.keys.__len__():
            #     # percorre Chaves conhecidas
            #     if not self.symmetric_key.__len__():
            #         self.generate_key()
            #         for id, publicKey in self.keys.items():
            #             msg = json.dumps({
            #                 "to": id,
            #                 ""origin"": self.id,
            #                 "publicKey": cast_to_str(serialize_rsa_public_key(self.public_key)),
            #                 "symmetricKey": cast_to_str(encrypt_rsa(self.symmetric_key, publicKey)),
            #                 "sign": cast_to_str(sign(self.symmetric_key, self.private_key))
            #             })
            #             self.send_to_clients(
            #                 msg, SENDING_SYMMETRIC_KEY)
            #         continue

            time.sleep(1)
            if self.symmetric_key == b'':
                continue
            print("symmetric_key mudou:", self.symmetric_key)

            print("Voce poderá estar recebendo mensagens, escreva a sua:\n")
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue

            # criptografar mensagem
            encrypt_fernet_msg = self.encrypt_fernet(msg)
            message_info: SocketMessageDefault = {
                "message": cast_to_str(b64encode(encrypt_fernet_msg)),
                "sign": cast_to_str(b64encode(hash(encrypt_fernet_msg)))
            }

            print("\tSending...\n")
            self.send_to_clients(json.dumps(message_info), SENDING_MESSAGE)
        return (1)


class Server(threading.Thread):
    client: Client

    def __init__(self, client: Client):
        super().__init__()
        self.receive = client.sock
        self.client = client

    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    # recebe mensagem
                    s = item.recv(1024*4)
                    # print('s type is', type(s), ', and your value is', s)
                    if s != b'' and s != '':
                        chunk: bytes = s
                        # print('Received new message')
                        # interpreta a mensagem como json e esparasse q seja do meu tipo SocketMessage
                        sck_msg: SocketMessage = json.loads(
                            chunk.decode(FORMAT))
                        # print("message from", sck_msg["senderName"])

                        sender_id = sck_msg["senderId"]
                        # verificar se estou recebendo mensagem minha, se sim ignorar
                        if sender_id == self.client.id:
                            print('ignoring message, because is mine')
                            # mensagem é minha, ignorando
                            continue

                        msg_type = sck_msg["msg_type"]

                        if msg_type == SENDING_PUBLIC_TOKEN:
                            # esse cliente esta recebendo a PublicKey de alguém

                            # TODO: TO AKI 1, error on deserialize
                            # converter str da mensagem em RSAPublicKey
                            new_public_key = deserialize_rsa_public_key(
                                sck_msg["msg"])
                            if new_public_key is None:
                                # mensagem não é uma PublicKey, ignorando
                                print('new_public_key is None')
                                continue

                            # salvando relação RSAPublicKey com o dono
                            new_public_key_owner = sender_id
                            self.client.keys[new_public_key_owner] = new_public_key

                            if self.client.symmetric_key == b'':  # não tenho chave síncrona
                                print("gerando symmetric_key")

                                # gerar chave síncrona nova
                                self.client.generate_key()

                            # enviar chave síncrona (usar RSA-encrypt)
                            # enviar minha chave Publica
                            # enviar HASH da chave síncrona (usar RSA-encrypt)
                            msg = json.dumps(self.client.payload_to_send_symmetric_key(
                                new_public_key_owner, new_public_key))

                            print("enviando symmetric_key")
                            self.client.send_to_clients(
                                msg, SENDING_SYMMETRIC_KEY)

                        elif msg_type == SENDING_SYMMETRIC_KEY:
                            # esse cliente esta recebendo a SymmetricKey de alguém

                            # convert str em dicionario
                            infos_json: SocketMessageSymmetricKey = json.loads(
                                sck_msg["msg"])

                            if not (infos_json["to"] == self.client.id):
                                # não é para esse cliente, ignorando
                                continue
                            print("recebendo symmetric_key")

                            # ===== Passo 1 =====
                            # pegar publicKey de quem esta enviando
                            coming_public_key = deserialize_rsa_public_key(
                                infos_json["publicKey"])
                            if coming_public_key is None:
                                # mensagem não é uma PublicKey, ignorando
                                continue

                            # guardar relação da publicKey com quem esta enviando ela
                            coming_public_key_owner = sck_msg["senderId"]
                            self.client.keys[coming_public_key_owner] = coming_public_key
                            print("salvando public_key")

                            # ===== Passo 2 =====
                            # pegar assinatura de quem esta enviando
                            coming_sign = b64decode(
                                cast_to_bytes(infos_json["sign"]))
                            # descriptografar assinatura de quem esta enviando (encontrar o hash da chave)
                            # é automático no verify

                            # ===== Passo 3 =====
                            # pegar chave síncrona criptografada de quem esta enviando
                            coming_symmetric_key_encrypted = b64decode(
                                cast_to_bytes(infos_json["symmetricKey"]))
                            # descriptografar chave síncrona criptografada de quem esta enviando
                            coming_symmetric_key = decrypt_rsa(
                                coming_symmetric_key_encrypted, self.client.private_key)
                            # hash da chave síncrona de quem esta enviando
                            # é automático no verify

                            # ===== Passo 4 =====
                            # verificar se os hashing batem
                            verified = verify(
                                coming_sign, coming_symmetric_key, coming_public_key)

                            if not verified:
                                print("sign not valid")
                                continue
                            print("symmetric_key verified")

                            # ===== Passo 5 =====
                            coming_symmetric_key_time_stamp = infos_json["symmetricKeyTimeStamp"]
                            # verificar se tenho a chave síncrona
                            if self.client.symmetric_key == b'' or self.client.symmetric_key_time_stamp > coming_symmetric_key_time_stamp:  # não tenho chave síncrona

                                print("atualizando symmetric_key")
                                # não tenho a chave síncrona, adicionando
                                # OU
                                # recebi a mais antiga (prioritária), me atualizo para essa
                                self.client.update_key(
                                    coming_symmetric_key, coming_symmetric_key_time_stamp)

                            # tenho, verificar se a chave síncrona é mais antiga (prioritária) que a atual
                            elif self.client.symmetric_key_time_stamp < coming_symmetric_key_time_stamp:
                                # tenho a mais antiga (prioritária), mandar essa para quem me enviou a mais recente (inútil)

                                print("retornando symmetric_key correta")
                                # enviar chave síncrona (usar RSA-encrypt)
                                # enviar minha chave Publica
                                # enviar HASH da chave síncrona (usar RSA-encrypt)
                                msg = json.dumps(self.client.payload_to_send_symmetric_key(
                                    coming_public_key_owner, coming_public_key))

                                self.client.send_to_clients(
                                    msg, SENDING_SYMMETRIC_KEY)

                        elif msg_type == SENDING_MESSAGE:
                            # mensagem normal

                            # convert str em dicionario
                            infos_message: SocketMessageDefault = json.loads(
                                sck_msg["msg"])

                            # pega a mensagem encriptada
                            message_encrypted = infos_message["message"]

                            sign = b64decode(
                                cast_to_bytes(infos_message["sign"]))

                            # descriptografar mensagem
                            msg_bytes = (self.client.decrypt_fernet(b64decode(
                                cast_to_bytes(message_encrypted))))
                            msg: str = cast_to_str(msg_bytes)


                            # verificar se os hashing batem
                            verified = sign == hash(msg_bytes)

                            if not verified:
                                print("message not valid")
                                continue

                            # mostrar mensagem
                            sender_name = sck_msg["senderName"]
                            print(sender_name + ":", msg)

                        if self.client.symmetric_key != b'':
                            print("\n>>", end='')

                except:
                    traceback.print_exc(file=sys.stdout)
                    break


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
