
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cast import cast_to_bytes


############# Hash #############################

def hash(content: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(content)
    return digest.finalize()


############# RSA ##############################

def encrypt_rsa(message: str | bytes, key: RSAPublicKey) -> bytes:
    # decriptando com chave publica
    return key.encrypt(cast_to_bytes(message), padding=padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ))


def decrypt_rsa(cipher_text: str | bytes, key: RSAPrivateKey) -> bytes:
    # decriptando com chave privada
    try:
        return key.decrypt(cast_to_bytes(cipher_text), padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
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


def verify(signature: bytes, message: str | bytes, key: RSAPublicKey) -> bool:
    # verificando assinatura com chave publica
    try:
        key.verify(
            signature,
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


def deserialize_rsa_public_key(data: bytes) -> RSAPublicKey | None:

    try:
        key = serialization.load_der_public_key(data)
        if isinstance(key, RSAPublicKey):
            return key
        print("key deserialized is not a RSAPublicKey")
        return None
    except:
        print("error on try deserialize key")
        return None