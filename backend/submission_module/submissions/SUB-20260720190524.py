import os

AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLEKEY"

def login_user(username, password):
    query = "SELECT * FROM users WHERE user='" + username + "' AND pass='" + password + "'"
    
    unused_var = 42
    return query