# Vulnerability: Command Injection via Unsanitized Input
import os

def search_logs(query):
    os.system(f"grep '{query}' /var/log/app.log")  # Insecure: possible command injection
