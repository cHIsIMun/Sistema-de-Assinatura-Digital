from flask import render_template, request, redirect, url_for, session
from sqlalchemy.exc import IntegrityError
from . import app, db
from .models import User
from .auth import hash_password
from .schemas import UserCreate, UserLogin
from pydantic import ValidationError
from .crypto import generate_keys, encrypt_private_key, decrypt_private_key
from flask import flash
from werkzeug.utils import secure_filename
import hashlib
from .models import Document
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import io
from flask import send_file


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            user_data = UserCreate(**request.form)
        except ValidationError as e:
            return render_template('register.html', error=e.errors())
        new_user = User(
            username=user_data.username,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            password_hash=hash_password(user_data.password)
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Usuário cadastrado com sucesso! Por favor, faça login.", "success")
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            error = "Usuário já existe. Por favor, escolha outro nome de usuário."
            return render_template('register.html', error=error)
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            user_data = UserLogin(**request.form)
        except ValidationError as e:
            return render_template('login.html', error=e.errors())
        user = User.query.filter_by(username=user_data.username, password_hash=hash_password(user_data.password)).first()
        if user:
            session['logged_in'] = True
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            return 'Login failed. Please check your credentials.', 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    keys_generated = user.public_key is not None
    
    return render_template('home.html', user=user, keys_generated=keys_generated)

@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys_view():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        # Gerar as chaves
        public_key, encrypted_private_key = generate_keys(password)
        
        # Armazenar as chaves no banco de dados
        user.public_key = public_key
        user.encrypted_private_key = encrypted_private_key  # Salvando a chave privada criptografada
        db.session.commit()
        
        return redirect(url_for('home'))
    
    return render_template('generate_keys.html')

@app.route('/view_public_key')
def view_public_key():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.public_key:
        return render_template('view_key.html', key=user.public_key, key_type="Pública")
    else:
        flash("Chave pública não encontrada.")
        return redirect(url_for('home'))

@app.route('/view_private_key', methods=['GET', 'POST'])
def view_private_key():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        password = request.form.get('password')
        try:
            private_key = decrypt_private_key(user.encrypted_private_key, password)
            return render_template('view_key.html', key=private_key, key_type="Privada")
        except Exception as e:
            flash("Erro ao descriptografar a chave privada. Verifique a senha e tente novamente.")
            return redirect(url_for('view_private_key'))
    
    return render_template('enter_password.html', 
                           action_title="Inserir Senha",
                           action_heading="Inserir Senha para Ver Chave Privada",
                           action_button_text="Ver Chave Privada")


@app.route('/upload_document', methods=['GET', 'POST'])
def upload_document():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            content = file.read()  # Ler o arquivo como binário
            doc_hash = hashlib.sha256(content).hexdigest()

            # Salvar documento no banco de dados
            new_document = Document(
                name=filename,
                content=content,  # Armazenar o conteúdo binário
                hash=doc_hash,
                user_id=user.id
            )
            db.session.add(new_document)
            db.session.commit()
            return redirect(url_for('list_documents'))
    
    return render_template('upload_document.html')

@app.route('/sign_document/<int:document_id>', methods=['GET', 'POST'])
def sign_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    document = Document.query.get_or_404(document_id)

    if request.method == 'POST':
        password = request.form.get('password')
        try:
            private_key = decrypt_private_key(user.encrypted_private_key, password)
            private_key_obj = serialization.load_pem_private_key(
                private_key.encode(),
                password=None,
                backend=default_backend()
            )

            # Assinar o conteúdo binário do documento
            signature = private_key_obj.sign(
                document.content,  # Assinando o conteúdo binário diretamente
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Criar um novo PDF com a assinatura embutida
            signed_content = document.content + b"\nSignature: " + signature

            # Atualizar o documento no banco de dados
            document.content = signed_content
            document.signature = signature.hex()
            document.signed_at = datetime.utcnow()
            db.session.commit()

            return redirect(url_for('list_documents'))
        except Exception as e:
            flash("Erro ao assinar o documento. Verifique a senha e tente novamente.")
            return redirect(url_for('sign_document', document_id=document_id))
    
    return render_template('enter_password.html', 
                           action_title="Inserir Senha",
                           action_heading="Inserir Senha para Assinar Documento",
                           action_button_text="Assinar Documento")

@app.route('/documents')
def list_documents():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    documents = Document.query.filter_by(user_id=user.id).all()

    return render_template('list_documents.html', documents=documents)

@app.route('/view_document/<int:document_id>')
def view_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document = Document.query.get_or_404(document_id)

    if document.name.endswith('.pdf'):
        return render_template('view_pdf_document.html', document=document)
    else:
        try:
            content = document.content.decode('utf-8')
        except UnicodeDecodeError:
            content = "Este arquivo não é um texto legível."

        return render_template('view_document.html', document=document, content=content)


@app.route('/verify_document/<int:document_id>')
def verify_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document = Document.query.get_or_404(document_id)
    user = User.query.get(document.user_id)

    public_key = serialization.load_pem_public_key(user.public_key.encode(), backend=default_backend())

    try:
        public_key.verify(
            bytes.fromhex(document.signature),
            document.hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        flash("A assinatura é válida.")
    except Exception:
        flash("A assinatura não pôde ser verificada ou é inválida.")

    return redirect(url_for('view_document', document_id=document_id))

@app.route('/verify_document_home', methods=['GET', 'POST'])
def verify_document_home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document_info = None
    verification_result = None

    if request.method == 'POST':
        file = request.files['file']
        if file:
            content = file.read()

            # Tentar encontrar um documento no banco de dados com o mesmo conteúdo
            documents = Document.query.all()
            for document in documents:
                if content.startswith(document.content[:-len(document.signature)]) and content.endswith(b"Signature: " + bytes.fromhex(document.signature)):
                    document_info = {
                        "name": document.name,
                        "signed": document.signature is not None,
                        "user": document.user
                    }
                    verification_result = "A assinatura é válida e foi encontrada no sistema."
                    break
            else:
                verification_result = "Documento não encontrado no sistema ou não assinado."

    return render_template('verify_document_home.html', document_info=document_info, verification_result=verification_result)

@app.route('/download_document/<int:document_id>')
def download_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document = Document.query.get_or_404(document_id)

    return send_file(
        io.BytesIO(document.content),
        as_attachment=True,
        download_name=document.name,
        mimetype='application/pdf'
    )
