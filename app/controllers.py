from .models import User, Document
from .auth import hash_password
from .crypto import generate_keys, decrypt_private_key
from werkzeug.utils import secure_filename
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import json
import io


# ================================
# User Authentication and Session
# ================================
def create_user(user_data):
    user = User(
        username=user_data.username,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        password_hash=hash_password(user_data.password)
    )
    return user

def get_user_by_credentials(username, password):
    password_hash = hash_password(password)
    return User.query.filter_by(username=username, password_hash=password_hash).first()

def get_user_by_id(user_id):
    return User.query.get(user_id)


# ================================
# Key Management
# ================================
def generate_user_keys(password):
    public_key, encrypted_private_key = generate_keys(password)
    return public_key, encrypted_private_key

def decrypt_user_private_key(encrypted_private_key, password):
    return decrypt_private_key(encrypted_private_key, password)


# ================================
# Document Management
# ================================
def process_document_upload(file, user_id):
    filename = secure_filename(file.filename)
    content = file.read()
    doc_hash = hashlib.sha256(content).hexdigest()

    new_document = Document(
        name=filename,
        content=content,
        hash=doc_hash,
        user_id=user_id
    )
    return new_document

def sign_document_content(document, private_key_obj, user):
    """
    Função para assinar o conteúdo de um documento.
    """
    # Assinando o conteúdo binário do documento
    signature = private_key_obj.sign(
        document.content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Estrutura da assinatura (em JSON)
    signature_metadata = {
        "signature": signature.hex(),
        "user": {
            "id": user.id,
            "username": user.username,
            "name": f"{user.first_name} {user.last_name}"
        },
        "signed_at": datetime.utcnow().isoformat()
    }
    
    # Embutir a assinatura no final do arquivo (JSON)
    signed_content = document.content + b"\n---SIGNATURE---\n" + json.dumps(signature_metadata).encode()
    
    return signed_content, signature_metadata

def extract_signature_from_file(content):
    """
    Extrai a assinatura do arquivo baseado no delimitador `---SIGNATURE---`.
    Retorna o conteúdo original e os metadados da assinatura, se existirem.
    """
    try:
        # Separar o conteúdo principal do JSON da assinatura
        content, signature_part = content.rsplit(b"\n---SIGNATURE---\n", 1)
        signature_metadata = json.loads(signature_part.decode())
        return content, signature_metadata
    except ValueError:
        return content, None

def verify_signature(public_key, content, signature_metadata):
    """
    Verifica a assinatura digital de um documento usando a chave pública do usuário.
    """
    try:
        # Converte a assinatura de hexadecimal para binário
        signature = bytes.fromhex(signature_metadata["signature"])
        
        # Verifica a assinatura contra o conteúdo original
        public_key.verify(
            signature,
            content,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def get_all_documents_by_user(user_id):
    """
    Retorna todos os documentos de um usuário específico.
    """
    return Document.query.filter_by(user_id=user_id).all()

def get_document_by_id(document_id):
    """
    Retorna um documento por ID ou gera um 404 se não encontrado.
    """
    return Document.query.get_or_404(document_id)
