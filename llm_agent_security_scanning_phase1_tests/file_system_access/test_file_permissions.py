# Vulnerability: Insecure File Permissions
import os

def create_file():
    with open("/tmp/insecure.txt", "w") as f:
        f.write("sensitive data")
    os.chmod("/tmp/insecure.txt", 0o777)  # Overly permissive
