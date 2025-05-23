# Vulnerability: Arbitrary Python Code Execution
def execute_code(code_str):
    exec(code_str)  # Insecure: allows arbitrary code execution
