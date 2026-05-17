from werkzeug.security import generate_password_hash
import sqlite3

username = "admin"
password = generate_password_hash("123456")
role = "admin"

conn = sqlite3.connect('database.db')
c = conn.cursor()

c.execute(
    "INSERT INTO users(username,password,role) VALUES(?,?,?)",
    (username,password,role)
)

conn.commit()
conn.close()

print("Administrador creado")
