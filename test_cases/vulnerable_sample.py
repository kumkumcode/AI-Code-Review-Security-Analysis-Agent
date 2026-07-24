import sqlite3

# SECURITY RISK: Hardcoded AWS Credential
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE" 

def fetch_user_data(user_id):
    # SECURITY RISK: Direct SQL String Formatting (SQL Injection)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM accounts WHERE id = '{user_id}'" 
    cursor.execute(query)
    return cursor.fetchall()

def highly_complex_smell(x):
    # CODE SMELL: High Cognitive Complexity (Deep Nesting)
    if x > 0:
        if x < 10:
            if x % 2 == 0:
                print("Even single digit")
            else:
                if x == 5:
                    print("Lucky five")
                else:
                    print("Odd single digit")
    return x