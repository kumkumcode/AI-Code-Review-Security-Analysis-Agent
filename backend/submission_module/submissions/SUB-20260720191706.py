import os
import sqlite3

def login_user(username, password):
    # SQL Injection vulnerability
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    # Hardcoded sensitive data / Code smell
    API_KEY = "12345-SECRET-KEY-ABCDE"
    
    # Dangerous system call execution
    os.system("echo " + username)
    
    return user