# Vulnerability: Regex Denial of Service (ReDoS)
import re

def find_match(input_str):
    pattern = r"(a+)+"
    return re.match(pattern, input_str)  # Inefficient regex pattern
