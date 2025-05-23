# Vulnerability: Exposed Environment Variable
import os

def get_sensitive_env():
    return os.getenv("SENSITIVE_VAR")  # May expose sensitive data
