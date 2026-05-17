from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import logging

app = Flask(__name__)
app.secret_key = "clave_super_segura"

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs("uploads", exist_ok=True)
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename='logs/security.log',
    level=logging.INFO,
    format='%(asctime)s %(message)s'
)

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')

    conn.commit()
    conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            session['user'] = username
            session['role'] = user[3]

            logging.info(f"LOGIN EXITOSO: {username}")

            return redirect('/dashboard')

        else:
            logging.warning(f"LOGIN FALLIDO: {username}")
            flash("Credenciales incorrectas")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect('/')

    return render_template('dashboard.html')

@app.route('/users')
def users():

    if 'user' not in session:
        return redirect('/')

    if session['role'] != 'admin':
        return "Acceso denegado"

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT username, role FROM users")
    users = c.fetchall()

    conn.close()

    return render_template('users.html', users=users)

@app.route('/upload', methods=['GET', 'POST'])
def upload():

    if 'user' not in session:
        return redirect('/')

    if request.method == 'POST':

        if 'file' not in request.files:
            return "No se seleccionó archivo"

        file = request.files['file']

        if file.filename == '':
            return "Archivo inválido"

        if file and allowed_file(file.filename):

            filename = secure_filename(file.filename)

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            logging.info(f"ARCHIVO SUBIDO: {filename}")

            return "Archivo subido correctamente"

        else:
            logging.warning("INTENTO DE SUBIDA NO PERMITIDA")
            return "Tipo de archivo no permitido"

    return render_template('upload.html')

@app.route('/protected')
def protected():

    if 'user' not in session:
        return redirect('/')

    return render_template('protected.html')

@app.route('/logout')
def logout():

    user = session.get('user')

    logging.info(f"LOGOUT: {user}")

    session.clear()

    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
