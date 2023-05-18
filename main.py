from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta
import json
import sqlite3
import re
import os
import threading

app = Flask(__name__)
app.secret_key = "dkzdroid"  # Chave secreta para criptografia de sessão

# Cria um objeto threading.local para armazenar os objetos SQLite específicos da thread
local = threading.local()

def get_connection():
    # Verifica se já existe uma conexão para a thread atual
    if not hasattr(local, 'connection'):
        # Cria uma nova conexão se nenhuma existir
        local.connection = sqlite3.connect('users.db')
        local.cursor = local.connection.cursor()
    return local.connection, local.cursor


conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Create the 'users' table if it doesn't exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        nome TEXT,
        password TEXT,
        valid_until TEXT
    )
""")

# Insert user data into the 'users' table
def insert_user_data():
    user_data = [
        ('usuario1@gmail.com', 'Danielzin', 'senha1', '2022-08-20'),
        ('alcapone@al.c', 'Alcapone', '123456', '2023-07-20'),
        ('trial@trial.com', 'Trial', 'senha3', '2023-05-15'),
        ('cliente@84.com', 'Indisponivel..', '1231232', '2023-08-12'),
        ('anderson@pdouble.com', 'Anderson', 'Double574', '2023-08-12')
    ]

    conn, cursor = get_connection()  # Get the connection and cursor
    for user in user_data:
        try:
            cursor.execute("INSERT INTO users (email, nome, password, valid_until) VALUES (?, ?, ?, ?)", user)
            conn.commit()
        except sqlite3.IntegrityError:
            print(f"Registro com email '{user[0]}' já existe. Ignorando a inserção..")

    cursor.close()  # Close the cursor




@app.route('/')
def index():
    return render_template("login.html")


@app.route('/notification', methods=['POST'])
def handle_notification():
    data = request.get_json()
    email = data['email']
    password = 'senha3'  # Senha padrão
    valid_until = datetime.date.today() + timedelta(
        days=30)  # Data de validade é 30 dias após a compra

    # Criar o dicionário com os dados do usuário
    user_data = {
        'password': password,
        'valid_until': valid_until.strftime('%Y-%m-%d')
    }

    # Salvar os dados do usuário em algum lugar, como um banco de dados
    # Aqui, estamos apenas retornando os dados como resposta para fins de demonstração
    return jsonify({email: user_data})


@app.route("/login", methods=["GET", "POST"])
def login():
    # Obter dados do formulário de login
    username = request.form.get("username")
    password = request.form.get("password")

    # Verificar credenciais no banco de dados
    conn, cursor = get_connection()
    cursor.execute("SELECT * FROM users WHERE email = ?", (username,))
    user = cursor.fetchone()

    if user is None or password != user[2]:
        error = True
        # cursor.close()  # Remova esta linha
        # conn.close()  # Remova esta linha
        return render_template("login.html", error=error)

    # Verificar a validade do usuário
    valid_until = datetime.strptime(user[3], "%Y-%m-%d")
    if valid_until < datetime.now():
        # cursor.close()  # Remova esta linha
        # conn.close()  # Remova esta linha
        return render_template("error.html", message="Data de validade expirada!")

    # Definir a sessão do usuário após o login bem-sucedido
    session["username"] = username

    # Atualizar a data de validade do usuário
    new_valid_until = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
    cursor.execute("UPDATE users SET valid_until = ? WHERE email = ?", (new_valid_until, username))
    conn.commit()

    # Remova as linhas abaixo, pois a conexão será fechada automaticamente ao final da solicitação
    # cursor.close()
    # conn.close()

    # Redirecionar para a página inicial após o login bem-sucedido
    return redirect(url_for("home"))

@app.route("/home", methods=["GET", "POST"])
def home():
    # Verificar se o usuário está autenticado
    if "username" not in session:
        return redirect(url_for("index"))

    # Obter o nome de usuário da sessão
    username = session["username"]

    # Recuperar informações do usuário no banco de dados
    conn, cursor = get_connection()
    cursor.execute("SELECT * FROM users WHERE email = ?", (username,))
    user = cursor.fetchone()
    valid_until = user[3]
    nome = user[1]

    # Formatar a data de validade para exibição
    valid_until = datetime.strptime(valid_until, "%Y-%m-%d").strftime("%d/%m/%Y")

    return render_template("home.html",
                           username=username,
                           valid_until=valid_until,
                           nome=nome)


@app.route('/mines')
def gerador():
    # Verificar se o usuário está autenticado
    if "username" not in session:
        return redirect(url_for("index"))

    # Obter o nome de usuário da sessão
    username = session["username"]

    # Recuperar informações do usuário no banco de dados
    conn, cursor = get_connection()
    cursor.execute("SELECT * FROM users WHERE email = ?", (username,))
    user = cursor.fetchone()
    valid_until = user[3]

    # Formatar a data de validade para exibição
    valid_until = datetime.strptime(valid_until, "%Y-%m-%d").strftime("%d/%m/%Y")

    return render_template("gerador.html",
                           username=username,
                           valid_until=valid_until)


@app.route("/logout")
def logout():
    # Remover a sessão do usuário
    session.pop("username", None)

    # Redirecionar para a página de login
    return redirect(url_for("index"))




@app.route("/adminlogin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        admin_username = request.form.get("admin_username")
        admin_password = request.form.get("admin_password")

        # Perform admin authentication logic here
        if admin_username == 'admin' and admin_password == 'admin_password':
            session['admin_authenticated'] = True
            return redirect(url_for('home_admin'))
        else:
            return render_template('admin_login.html', error='Invalid admin credentials.')

    # Render the login form for GET requests
    return render_template('admin_login.html')

@app.route("/homeadmin", methods=["GET", "POST"])
def home_admin():
    if 'admin_authenticated' not in session or not session['admin_authenticated']:
        return jsonify({'error': 'Admin not authenticated.'}), 401

    conn, cursor = get_connection()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    # cursor.close()
    # conn.close()

    return render_template("home_admin.html", users=users)
conn.commit()


@app.route("/admin/users/create", methods=["POST"])
def create_user():
    if 'admin_authenticated' not in session or not session['admin_authenticated']:
        return jsonify({'error': 'Admin not authenticated.'}), 401

    email = request.form.get("email")
    nome = request.form.get("nome")
    password = request.form.get("password")
    valid_until = request.form.get("valid_until")

    conn, cursor = get_connection()
    try:
        cursor.execute("INSERT INTO users (email, nome, password, valid_until) VALUES (?, ?, ?, ?)",
                       (email, nome, password, valid_until))
        conn.commit()
        return jsonify({'message': 'User created successfully.'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User with the same email already exists.'}), 400
conn.commit()


@app.route("/admin/users/<email>", methods=["GET"])
def get_user(email):
    if 'admin_authenticated' not in session or not session['admin_authenticated']:
        return jsonify({'error': 'Admin not authenticated.'}), 401

    conn, cursor = get_connection()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user:
        user_data = {
            'email': user[0],
            'nome': user[1],
            'password': user[2],
            'valid_until': user[3]
        }
        return jsonify(user_data)
    else:
        return jsonify({'error': 'User not found.'}), 404
conn.commit()


@app.route("/admin/users/<email>/update", methods=["POST"])
def update_user(email):
    if 'admin_authenticated' not in session or not session['admin_authenticated']:
        return jsonify({'error': 'Admin not authenticated.'}), 401

    nome = request.form.get("nome")
    password = request.form.get("password")
    valid_until = request.form.get("valid_until")

    conn, cursor = get_connection()
    try:
        cursor.execute("UPDATE users SET nome = ?, password = ?, valid_until = ? WHERE email = ?",
                       (nome, password, valid_until, email))
        conn.commit()
        return jsonify({'message': 'User updated successfully.'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User with the same email already exists.'}), 400
conn.commit()


@app.route("/admin/users/<email>/delete", methods=["POST"])
def delete_user(email):
    if 'admin_authenticated' not in session or not session['admin_authenticated']:
        return jsonify({'error': 'Admin not authenticated.'}), 401

    conn, cursor = get_connection()
    cursor.execute("DELETE FROM users WHERE email = ?", (email,))

    return jsonify({'message': 'User deleted successfully.'})
conn.commit()




if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))
