# Vulnerability: Temporary File Storage Risks
def write_temp_file(data):
    with open("/tmp/tempfile.txt", "w") as f:
        f.write(data)  # Insecure: predictable temp file path
