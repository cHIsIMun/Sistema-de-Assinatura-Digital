from flask import render_template, request, redirect, url_for, session, flash, send_file
from . import app, db
from .controllers import *
from .schemas import UserCreate, UserLogin
from pydantic import ValidationError
import io

# ========================================
# Auth Routes (Login, Register, Logout)
# ========================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            user_data = UserCreate(**request.form)
        except ValidationError as e:
            return render_template('auth/register.html', error=e.errors())
        
        new_user = create_user(user_data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            user_data = UserLogin(**request.form)
        except ValidationError as e:
            return render_template('auth/login.html', error=e.errors())
        
        user = get_user_by_credentials(user_data.username, user_data.password)
        if user:
            session['logged_in'] = True
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your credentials.')
            return redirect(url_for('login'))
    
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))


# ========================================
# Home and Key Management
# ========================================

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = get_user_by_id(session['user_id'])
    keys_generated = user.public_key is not None
    return render_template('layouts/home.html', user=user, keys_generated=keys_generated)

@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys_view():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = get_user_by_id(session['user_id'])
    
    if request.method == 'POST':
        password = request.form.get('password')
        public_key, encrypted_private_key = generate_user_keys(password)
        
        user.public_key = public_key
        user.encrypted_private_key = encrypted_private_key
        db.session.commit()
        
        return redirect(url_for('home'))
    
    return render_template('keys/generate_keys.html')

@app.route('/view_public_key')
def view_public_key():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = get_user_by_id(session['user_id'])
    if user.public_key:
        return render_template('keys/view_key.html', key=user.public_key, key_type="Pública")
    else:
        flash("Chave pública não encontrada.")
        return redirect(url_for('home'))

@app.route('/view_private_key', methods=['GET', 'POST'])
def view_private_key():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = get_user_by_id(session['user_id'])
    
    if request.method == 'POST':
        password = request.form.get('password')
        try:
            private_key = decrypt_user_private_key(user.encrypted_private_key, password)
            return render_template('keys/view_key.html', key=private_key, key_type="Privada")
        except Exception:
            flash("Erro ao descriptografar a chave privada. Verifique a senha e tente novamente.")
            return redirect(url_for('view_private_key'))
    
    return render_template('shared/enter_password.html', action_title="Inserir Senha", action_heading="Inserir Senha para Ver Chave Privada", action_button_text="Ver Chave Privada")


# ========================================
# Document Management (Upload, Sign, View, Verify)
# ========================================

@app.route('/upload_document', methods=['GET', 'POST'])
def upload_document():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            new_document = process_document_upload(file, session['user_id'])  # Chame a função corrigida aqui
            db.session.add(new_document)
            db.session.commit()
            return redirect(url_for('list_documents'))
    
    return render_template('documents/upload_document.html')

@app.route('/sign_document/<int:document_id>', methods=['GET', 'POST'])
def sign_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = get_user_by_id(session['user_id'])
    document = get_document_by_id(document_id)

    if request.method == 'POST':
        password = request.form.get('password')
        try:
            private_key = decrypt_user_private_key(user.encrypted_private_key, password)
            private_key_obj = serialization.load_pem_private_key(private_key.encode(), password=None, backend=default_backend())
            
            signed_content, signature_metadata = sign_document_content(document, private_key_obj, user)
            document.content = signed_content
            document.signature = signature_metadata["signature"]
            document.signed_at = datetime.utcnow()
            db.session.commit()
            
            return redirect(url_for('list_documents'))
        except Exception:
            flash("Erro ao assinar o documento. Verifique a senha e tente novamente.")
            return redirect(url_for('sign_document', document_id=document_id))
    
    return render_template('shared/enter_password.html', action_title="Inserir Senha", action_heading="Inserir Senha para Assinar Documento", action_button_text="Assinar Documento")

@app.route('/documents')
def list_documents():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    documents = get_all_documents_by_user(session['user_id'])
    return render_template('documents/list_documents.html', documents=documents)

@app.route('/view_document/<int:document_id>')
def view_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document = get_document_by_id(document_id)
    return render_template('documents/view_pdf_document.html', document=document)

@app.route('/verify_document/<int:document_id>')
def verify_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document = get_document_by_id(document_id)
    content, signature_metadata = extract_signature_from_file(document.content)
    
    if signature_metadata:
        user = get_user_by_id(signature_metadata["user"]["id"])
        public_key = serialization.load_pem_public_key(user.public_key.encode(), backend=default_backend())
        
        if verify_signature(public_key, content, signature_metadata):
            flash(f"A assinatura é válida e pertence a {signature_metadata['user']['name']}.")
        else:
            flash("A assinatura não pôde ser verificada ou é inválida.")
    else:
        flash("O documento não possui uma assinatura válida.")

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
            content, signature_metadata = extract_signature_from_file(content)

            if signature_metadata:
                user = get_user_by_id(signature_metadata["user"]["id"])
                public_key = serialization.load_pem_public_key(user.public_key.encode(), backend=default_backend())

                if verify_signature(public_key, content, signature_metadata):
                    verification_result = f"A assinatura é válida e pertence a {user.first_name} {user.last_name}."
                    document_info = {
                        "name": file.filename,
                        "user": user
                    }
                else:
                    verification_result = "A assinatura não pôde ser verificada ou é inválida."
            else:
                verification_result = "O documento não possui uma assinatura válida."

    return render_template('shared/verify_document_home.html', document_info=document_info, verification_result=verification_result)



@app.route('/download_document/<int:document_id>')
def download_document(document_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document = get_document_by_id(document_id)
    return send_file(io.BytesIO(document.content), as_attachment=True, download_name=document.name, mimetype='application/pdf')
