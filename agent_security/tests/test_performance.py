"""
Performance tests for the security scanner.
"""

import pytest
import time
import os
from pathlib import Path
import tempfile
import random
import string
from agent_security.scanner import scan_python_file, scan_yaml_content
from agent_security.models import RiskLevel
from unittest import mock

# Define sanitize_error function directly
def sanitize_error(error: Exception) -> str:
    """Mock sanitize_error function for testing."""
    return str(error)

# Add the sanitize_error function to the scanner module directly
@pytest.fixture(autouse=True)
def add_sanitize_error_function():
    import agent_security.scanner
    agent_security.scanner.sanitize_error = sanitize_error
    yield
    # Clean up after test
    if hasattr(agent_security.scanner, 'sanitize_error'):
        delattr(agent_security.scanner, 'sanitize_error')

# Function to generate a random Python file of specified size
def generate_random_python_file(size_kb):
    """Generate a random Python file of approximately the given size in KB."""
    content = """
import os
import subprocess
import requests

def main():
    # Some code
    pass

"""
    # Generate random functions to reach the target size
    while len(content.encode('utf-8')) < size_kb * 1024:
        func_name = ''.join(random.choices(string.ascii_lowercase, k=10))
        func_content = f"""
def {func_name}():
    # Random function
    x = "{''.join(random.choices(string.ascii_letters, k=50))}"
    y = {random.randint(1, 1000)}
    return x * y

"""
        content += func_content
        
        # Add some risky patterns occasionally
        if random.random() < 0.1:
            risky_pattern = random.choice([
                'os.system("ls -la")',
                'eval("2 + 2")',
                'subprocess.call(["rm", "-rf", "temp"])',
                'exec(user_input)',
                'requests.get(url)'
            ])
            content += f"    {risky_pattern}\n"
    
    return content

# Function to generate a random YAML file of specified size
def generate_random_yaml_file(size_kb):
    """Generate a random YAML file of approximately the given size in KB."""
    content = """
llm:
  model: gpt-3.5-turbo
  provider: openai
  temperature: 0.5

security:
  allowed_tools: ["search", "read"]
  restricted_commands: ["rm", "chmod"]
  allowed_domains: ["api.example.com"]

"""
    # Generate random YAML content to reach the target size
    tools = []
    while len(content.encode('utf-8')) < size_kb * 1024:
        tool_name = ''.join(random.choices(string.ascii_lowercase, k=10))
        tool_desc = ''.join(random.choices(string.ascii_letters + ' ', k=50))
        tool = f"""
  - name: {tool_name}
    description: "{tool_desc}"
    config:
      rate_limit: {random.randint(10, 100)}
      timeout: {random.randint(5, 30)}
"""
        tools.append(tool)
        
        # Add some risky patterns occasionally
        if random.random() < 0.1:
            risky_tool = random.choice([
                '  - name: shell\n    description: "Execute shell commands"',
                '  - name: file\n    description: "Access file system"',
                '  - name: code\n    description: "Execute Python code"'
            ])
            tools.append(risky_tool)
    
    content += "tools:\n" + "".join(tools)
    return content

@pytest.mark.slow
class TestScannerPerformance:
    """Performance tests for the scanner module."""
    
    @pytest.mark.parametrize("size_kb", [10, 50])
    def test_python_scanner_performance(self, size_kb):
        """Test scanner performance on Python files of different sizes."""
        # Generate a temporary Python file of the specified size
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
            content = generate_random_python_file(size_kb)
            temp.write(content.encode('utf-8'))
            file_path = temp.name
        
        try:
            # Measure scanning time
            start_time = time.time()
            ignored_findings = set()
            base_path = Path(file_path).parent
            report = scan_python_file(file_path, ignored_findings, base_path)
            end_time = time.time()
            
            # Calculate scan time and scan rate
            scan_time = end_time - start_time
            scan_rate = size_kb / scan_time if scan_time > 0 else float('inf')
            
            print(f"\nPython file size: {size_kb} KB")
            print(f"Scan time: {scan_time:.4f} seconds")
            print(f"Scan rate: {scan_rate:.2f} KB/s")
            print(f"Overall risk: {report.overall_risk.value}")
            
            # Assertions to verify scanning worked
            assert report is not None
            assert hasattr(report, 'overall_risk')
            
            # Very relaxed performance threshold - just ensure it completes
            assert scan_time < 20.0, f"Scanning {size_kb} KB file took too long: {scan_time} seconds"
            
        finally:
            # Clean up the temporary file
            if os.path.exists(file_path):
                os.unlink(file_path)
    
    @pytest.mark.parametrize("size_kb", [5, 20])
    def test_yaml_scanner_performance(self, size_kb):
        """Test scanner performance on YAML files of different sizes."""
        # Generate YAML content of the specified size
        content = generate_random_yaml_file(size_kb)
        
        # Measure scanning time
        start_time = time.time()
        ignored_findings = set()
        base_path = Path.cwd()
        report = scan_yaml_content(content, "test.yaml", ignored_findings, base_path)
        end_time = time.time()
        
        # Calculate scan time and scan rate
        scan_time = end_time - start_time
        scan_rate = size_kb / scan_time if scan_time > 0 else float('inf')
        
        print(f"\nYAML file size: {size_kb} KB")
        print(f"Scan time: {scan_time:.4f} seconds")
        print(f"Scan rate: {scan_rate:.2f} KB/s")
        print(f"Overall risk: {report.overall_risk.value}")
        
        # Assertions to verify scanning worked
        assert report is not None
        assert hasattr(report, 'overall_risk')
        
        # Very relaxed performance threshold - just ensure it completes
        assert scan_time < 15.0, f"Scanning {size_kb} KB file took too long: {scan_time} seconds"


if __name__ == "__main__":
    # Run the performance tests
    pytest.main(["-xvs", __file__]) 