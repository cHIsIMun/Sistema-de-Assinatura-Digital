# Sistema de Assinatura de Documentos Digitais

Este projeto implementa um sistema de assinatura de documentos digitais utilizando criptografia de chave assimétrica. Os usuários podem registrar-se, gerar chaves públicas e privadas, assinar documentos PDF, verificar assinaturas, e baixar documentos assinados.

## Funcionalidades

- **Registro e Autenticação de Usuários**
- **Geração de Chaves Públicas e Privadas**
- **Upload de Documentos**
- **Assinatura de Documentos**
- **Verificação de Assinaturas**
- **Visualização e Download de Documentos**

## Tecnologias Utilizadas

- **Python 3.12**
- **Flask**
- **SQLAlchemy**
- **Werkzeug**
- **Jinja2**
- **Cryptography**

## Configuração Inicial

### 1. Clonar o Repositório

Clone o repositório para o seu ambiente local:

```bash
git clone https://github.com/seu-usuario/seu-repositorio.git
cd seu-repositorio
```

### 2. Configurar o Ambiente Virtual

É recomendável criar um ambiente virtual para gerenciar as dependências do projeto:

```bash
python3 -m venv venv
source venv/bin/activate  # No Windows, use: venv\Scripts\activate
```

### 3. Instalar as Dependências

O projeto utiliza o `Poetry` para gerenciar as dependências. Instale as dependências com o seguinte comando:

```bash
poetry install
```

### 4. Configurar o Banco de Dados

Inicialize o banco de dados SQLite3:

```bash
poetry run python init_db.py
```

### 5. Rodar o Servidor

Execute o servidor Flask em modo de desenvolvimento:

```bash
flask run
```

### 6. Acessar a Aplicação

Abra o navegador e acesse:

```
http://127.0.0.1:5000
```

## Como Utilizar

### Registro e Login

1. **Registrar-se**: Acesse a página de registro, crie uma conta de usuário fornecendo nome de usuário, nome, sobrenome e senha.
2. **Login**: Faça login usando as credenciais criadas.

### Geração de Chaves

1. **Gerar Chaves**: Após o login, você pode gerar um par de chaves pública e privada. A chave privada será criptografada e armazenada no sistema.

### Upload e Assinatura de Documentos

1. **Upload de Documentos**: Faça upload de arquivos PDF para o sistema.
2. **Assinar Documentos**: Após o upload, você pode assinar os documentos com sua chave privada.

### Verificação de Assinaturas

1. **Verificar Assinatura**: Faça o upload de um documento para verificar se ele foi assinado e se a assinatura é válida.

### Download de Documentos

1. **Baixar Documento Assinado**: Você pode baixar os documentos assinados diretamente na página de visualização.

## Estrutura do Projeto

```bash
seu-projeto/
│
├── app/
│   ├── __init__.py         # Inicializa a aplicação Flask e configura o Jinja2
│   ├── routes.py           # Define as rotas e lógica do sistema
│   ├── models.py           # Define os modelos SQLAlchemy (User, Document)
│   ├── schemas.py          # Define os schemas Pydantic (UserCreate, UserLogin)
│   ├── auth.py             # Lida com autenticação e hashing de senhas
│   ├── crypto.py           # Lida com a geração e criptografia de chaves
│   └── templates/          # Contém os templates Jinja2
│       ├── base.html       # Template base para herança
│       ├── home.html       # Página inicial do sistema
│       ├── register.html   # Página de registro
│       ├── login.html      # Página de login
│       ├── upload_document.html # Página de upload de documentos
│       ├── sign_document.html   # Página de assinatura de documentos
│       ├── list_documents.html  # Página de listagem de documentos
│       ├── view_document.html   # Página de visualização de documentos
│       ├── view_pdf_document.html # Página de visualização de PDF
│       ├── enter_password.html  # Página para inserção de senha
│       └── verify_document_home.html # Página para verificação de assinatura
│
├── README.md               # Instruções de inicialização (este arquivo)
├── config.py               # Configurações da aplicação (opcional)
├── requirements.txt        # Dependências do projeto
└── run.py                  # Script para iniciar o servidor Flask
```
