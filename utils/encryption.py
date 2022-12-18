
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from utils.cast import cast_to_bytes
from cryptography.hazmat.backends import default_backend


############# Hash #############################

def hash(content: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(content)
    return digest.finalize()


############# RSA ##############################

def encrypt_rsa(message: str | bytes, key: RSAPublicKey) -> bytes:
    # decriptando com chave publica
    return key.encrypt(cast_to_bytes(message), padding=padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))


def decrypt_rsa(cipher_text: str | bytes, key: RSAPrivateKey) -> bytes:
    # decriptando com chave privada
    try:
        return key.decrypt(cast_to_bytes(cipher_text), padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    except:
        print("error ignored in decrypt_rsa")
        return bytes()


def sign(message: str | bytes, key: RSAPrivateKey) -> bytes:
    # assinando com chave privada
    return key.sign(cast_to_bytes(message), algorithm=hashes.SHA256(), padding=padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ))


def verify(signature: str | bytes, message: str | bytes, key: RSAPublicKey) -> bool:
    # verificando assinatura com chave publica
    try:
        key.verify(
            cast_to_bytes(signature),
            cast_to_bytes(message),
            algorithm=hashes.SHA256(),
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        )
        return True
    except:
        return False

############# RSA - serializes #################


def serialize_rsa_public_key(key: RSAPublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_rsa_public_key(data: bytes | str) -> RSAPublicKey | None:

    print("data to deserialize", data)
    # TODO: TO AKI 2, error on deserialize
    try:
        key = serialization.load_pem_public_key(
            cast_to_bytes(data),
            backend=default_backend()
        )
        if isinstance(key, RSAPublicKey):
            print("key deserialized", serialize_rsa_public_key(key))
            return key
        print("key deserialize is not a RSAPublicKey")
        return None
    except:
        print("error on try deserialize key")
        return None
