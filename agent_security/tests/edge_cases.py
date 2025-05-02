"""
Edge cases for testing the security scanner.
These cases test the scanner's ability to handle complex and unusual scenarios.
"""

import pytest
from agent_security.scanner import scan_yaml_content, scan_python_file
from agent_security.models import RiskLevel
import os
import tempfile

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
    report = scan_yaml_content(yaml_content, "test.yaml")
    assert len(report.findings) >= 4  # Should find multiple risks at different levels
    assert any(f.pattern == "risky_llm_model" for f in report.findings)
    assert any(f.pattern == "high_temperature" for f in report.findings)
    assert any(f.pattern == "unrestricted_tools" for f in report.findings)
    assert report.overall_risk == RiskLevel.CRITICAL

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
    report = scan_yaml_content(yaml_content, "test.yaml")
    assert len(report.findings) >= 2
    assert all(f.pattern == "unsafe_prompt_template" for f in report.findings)
    assert report.overall_risk == RiskLevel.HIGH

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
    report = scan_yaml_content(yaml_content, "test.yaml")
    assert len(report.findings) >= 3
    assert any(f.pattern == "risky_tool_description" for f in report.findings)
    assert any(f.pattern == "unsafe_logging" for f in report.findings)
    assert report.overall_risk == RiskLevel.HIGH

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
    report = scan_yaml_content(yaml_content, "test.yaml")
    assert len(report.findings) >= 2
    assert any(f.pattern == "missing_allowlist" for f in report.findings)
    assert any(f.pattern == "missing_rate_limits" for f in report.findings)
    assert report.overall_risk == RiskLevel.MEDIUM

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
    report = scan_yaml_content(yaml_content, "test.yaml")
    assert len(report.findings) >= 2
    assert any(f.pattern == "missing_rate_limits" for f in report.findings)
    assert report.overall_risk == RiskLevel.MEDIUM

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
        report = scan_python_file(f.name, ignored_findings, base_path)
        os.unlink(f.name)
    
    assert len(report.findings) >= 3
    assert any(f.pattern == "langchain" for f in report.findings)
    assert any(f.pattern == "ShellTool" for f in report.findings)
    assert any(f.pattern == "PythonREPLTool" for f in report.findings)
    assert report.overall_risk == RiskLevel.CRITICAL

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
        report = scan_yaml_content(yaml_content, f"test_{i}.yaml")
        assert report.overall_risk == RiskLevel.CRITICAL
        assert len(report.findings) > 0 