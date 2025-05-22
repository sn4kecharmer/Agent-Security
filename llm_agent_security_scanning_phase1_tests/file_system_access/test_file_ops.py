# Vulnerability: Unrestricted File Operations
import os

def delete_file(filename):
    os.remove(filename)  # Insecure: filename may point to critical system files
