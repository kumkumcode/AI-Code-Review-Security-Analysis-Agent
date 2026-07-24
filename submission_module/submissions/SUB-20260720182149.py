import os

def execute_user_command(user_input):
    print(f"Running command for input: {user_input}")
    # Insecure system execution vulnerable to command injection
    os.system("ping -c 1 " + user_input)

if __name__ == "__main__":
    execute_user_command("127.0.0.1; cat /etc/passwd")