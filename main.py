from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta
import sqlite3
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


# Create the 'users' table if it doesn't exist
def create_users_table():
    conn, cursor = get_connection()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            nome TEXT,
            password TEXT,
            valid_until TEXT
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


# Insert user data into the 'users' table
def insert_user_data():
    user_data = [
        ('usuario1@gmail.com', 'Daniel', 'senha1', '2022-08-20'),
        ('alcapone@al.c', 'Alcapone', '123456', '2023-07-20'),
        ('trial@trial.com', 'Trial', 'senha3', '2023-05-15'),
        ('cliente@84.com', 'Indisponivel..', '1231232', '2023-08-12'),
        ('anderson@pdouble.com', 'Anderson', 'Double574', '2023-08-12')
    ]

    conn, cursor = get_connection()
    for user in user_data:
        try:
            cursor.execute("INSERT INTO users (email, nome, password, valid_until) VALUES (?, ?, ?, ?)", user)
            conn.commit()
        except sqlite3.IntegrityError:
            print(f"Registro com email '{user[0]}' já existe. Ignorando a inserção.")

    cursor.close()
    conn.close()


@app.route('/')
def index():
    return render_template("login.html")


@app.route('/notification', methods=['POST'])
def handle_notification():
    data = request.get_json()
    email = data['email']
    password = 'senha3'  # Senha padrão
    valid_until = datetime.date.today() + timedelta(days=30)  # Data de validade é 30 dias após a compra

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
        return render_template("login.html", message="Credenciais inválidas. Tente novamente.")

    # Definir sessão
    session["email"] = username
    session["logged_in"] = True

    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Obter dados do formulário de registro
        email = request.form.get("email")
        nome = request.form.get("nome")
        password = request.form.get("password")
        valid_until = request.form.get("valid_until")

        # Verificar se o e-mail já está registrado
        conn, cursor = get_connection()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            return render_template("register.html", message="O e-mail já está registrado. Tente outro.")

        # Inserir novo usuário no banco de dados
        try:
            cursor.execute("INSERT INTO users (email, nome, password, valid_until) VALUES (?, ?, ?, ?)",
                           (email, nome, password, valid_until))
            conn.commit()
            return redirect(url_for("index"))
        except sqlite3.Error as e:
            return render_template("register.html", message="Erro ao registrar usuário. Tente novamente.")

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("index"))

    email = session.get("email")

    conn, cursor = get_connection()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user:
        return render_template("dashboard.html", user=user)

    return redirect(url_for("index"))


if __name__ == '__main__':
    create_users_table()
    insert_user_data()
    app.run(debug=True)
