# Vulnerability: Insecure Credential Storage
def store_password(password):
    with open("passwords.txt", "w") as f:
        f.write(password)  # Stored in plain text
