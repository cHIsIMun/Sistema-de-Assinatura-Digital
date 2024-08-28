from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

def generate_keys(password: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serializar a chave pública
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Serializar a chave privada
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Criptografar a chave privada usando a senha do usuário
    encrypted_private_key = encrypt_private_key(pem_private_key.decode('utf-8'), password)

    return pem_public_key.decode('utf-8'), encrypted_private_key

def encrypt_private_key(private_key: str, password: str):
    # Derivar uma chave simétrica da senha do usuário
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher_suite = Fernet(key)
    encrypted_private_key = cipher_suite.encrypt(private_key.encode())
    
    # Salvar o salt juntamente com a chave criptografada
    return base64.urlsafe_b64encode(salt + encrypted_private_key).decode('utf-8')

def decrypt_private_key(encrypted_private_key: str, password: str):
    # Decodificar e separar o salt da chave criptografada
    decoded_data = base64.urlsafe_b64decode(encrypted_private_key)
    salt = decoded_data[:16]
    encrypted_private_key = decoded_data[16:]

    # Derivar a chave simétrica a partir da senha e do salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher_suite = Fernet(key)
    
    # Descriptografar a chave privada
    private_key = cipher_suite.decrypt(encrypted_private_key)
    
    return private_key.decode('utf-8')
