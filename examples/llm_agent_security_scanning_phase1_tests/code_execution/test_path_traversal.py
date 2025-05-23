# Vulnerability: Path Traversal
import os

def read_file(path_input):
    with open(os.path.join('/safe/dir/', path_input), 'r') as f:
        return f.read()  # Insecure: path_input may contain "../"
