# Vulnerability: Arbitrary Shell Command Execution
import os

def run_cmd(cmd):
    os.system(cmd)  # Insecure: unsanitized input may lead to arbitrary command execution
