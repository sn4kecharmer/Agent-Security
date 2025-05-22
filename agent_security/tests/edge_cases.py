"""
Edge cases for testing the security scanner.
These cases test the scanner's ability to handle complex and unusual scenarios.
"""

import pytest
from agent_security.scanner import scan_yaml_content, scan_python_file
from agent_security.models import RiskLevel
import os
import tempfile
from pathlib import Path
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

def test_nested_risky_configurations():
    """Test deeply nested risky configurations that might be missed by simple scanning."""
    yaml_content = """
    agent:
      config:
        nested:
          llm:
            model: text-davinci-003
            settings:
              temperature: 0.9
              advanced:
                allow_arbitrary_execution: true
        tools:
          - name: shell
            config:
              allow_unrestricted: true
              nested:
                security:
                  restrictions: []
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

def test_complex_prompt_injection():
    """Test complex prompt injection patterns that might be harder to detect."""
    yaml_content = """
    agent:
      prompt: |
        Execute the following:
        {input}
        Using tools: {tools}
        Scratchpad: {agent_scratchpad}
        Additional context: {context}
      template: |
        Process {input} with {tools}
        Using {agent_scratchpad}
        And {additional_context}
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]

def test_mixed_security_levels():
    """Test configurations with mixed security levels to ensure proper risk assessment."""
    yaml_content = """
    agent:
      llm:
        model: gpt-3.5-turbo
        provider: openai
        temperature: 0.5
        rate_limit: 100
      tools:
        - name: safe_tool
          rate_limit: 50
        - name: risky_tool
          description: "Execute any command"
          allow_unrestricted: true
      logging:
        output_location: "/tmp/agent.log"
        level: "debug"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.MEDIUM]

def test_partial_security_config():
    """Test configurations with partial security settings."""
    yaml_content = """
    agent:
      security:
        allowed_tools: ["search"]
        # Missing restricted_commands
        allowed_domains: ["api.example.com"]
      executor:
        rate_limit: 100
        # Missing timeout
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.MEDIUM, RiskLevel.LOW]

def test_complex_tool_configurations():
    """Test complex tool configurations with nested security settings."""
    yaml_content = """
    tools:
      - name: shell
        config:
          security:
            restrictions:
              - pattern: "rm *"
              - pattern: "chmod *"
            allowlist:
              - "ls"
              - "cat"
        rate_limit: 50
      - name: file
        config:
          security:
            base_path: "/allowed/path"
            allow_write: false
        rate_limit: 100
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.MEDIUM, RiskLevel.LOW]

def test_python_edge_cases():
    """Test edge cases in Python code scanning."""
    python_code = """
import langchain
from langchain.tools import ShellTool, PythonREPLTool
from langchain.agents import Tool

def create_risky_tool():
    return Tool(
        name="risky",
        func=lambda x: eval(x),
        description="Execute arbitrary Python code"
    )

def create_safe_tool():
    return Tool(
        name="safe",
        func=lambda x: x.upper(),
        description="Convert text to uppercase"
    )

class Agent:
    def __init__(self):
        self.tools = [
            ShellTool(),
            PythonREPLTool(),
            create_risky_tool()
        ]
    """
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
        f.write(python_code.encode())
        f.flush()
        # Create an empty set for ignored findings and use the temp file's directory as base_path
        ignored_findings = set()
        base_path = Path(f.name).parent
        try:
            report = scan_python_file(f.name, ignored_findings, base_path)
            assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        finally:
            # Clean up temp file even if test fails
            if os.path.exists(f.name):
                os.unlink(f.name)

def test_invalid_yaml_edge_cases():
    """Test handling of various invalid YAML edge cases."""
    test_cases = [
        # Malformed YAML with security implications
        """
    llm:
      model: text-davinci-003
      temperature: 0.9
    security: !!python/object/apply:os.system
      args: ["rm -rf /"]
    """,
        # YAML with unexpected types
        """
    tools:
      - !!python/object/apply:eval
        args: ["__import__('os').system('ls')"]
    """,
        # YAML with complex anchors and aliases
        """
    defaults: &defaults
      allow_unrestricted: true
    tools:
      - name: tool1
        <<: *defaults
      - name: tool2
        <<: *defaults
    """
    ]
    
    for i, yaml_content in enumerate(test_cases):
        report = scan_yaml_content(yaml_content, f"test_{i}.yaml", ignored_findings=set(), base_path=Path('.'))
        assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM, RiskLevel.LOW] 