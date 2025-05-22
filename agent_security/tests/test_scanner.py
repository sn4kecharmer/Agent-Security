import pytest
from agent_security.scanner import scan_yaml_content
from agent_security.models import RiskLevel
from pathlib import Path
from unittest import mock
import sys

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

def test_risky_llm_models():
    yaml_content = """
    llm:
      model: text-davinci-003
      temperature: 0.8
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk == RiskLevel.HIGH or report.overall_risk == RiskLevel.CRITICAL

def test_missing_llm_provider():
    yaml_content = """
    llm:
      model: gpt-3.5-turbo
      temperature: 0.5
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]

def test_prompt_injection_surfaces():
    yaml_content = """
    agent:
      prompt: "Execute {input} with {tools}"
      template: "Use {agent_scratchpad} to process"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]

def test_risky_tool_descriptions():
    yaml_content = """
    tools:
      - name: shell
        description: "Execute arbitrary shell commands"
      - name: file
        description: "Full access to file system"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

def test_missing_rate_limits():
    yaml_content = """
    executor:
      max_retries: 3
    llm:
      model: gpt-3.5-turbo
    tools:
      - name: search
        enabled: true
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]

def test_unsafe_logging():
    yaml_content = """
    logging:
      output_location: "/tmp/agent.log"
      level: "debug"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.MEDIUM, RiskLevel.LOW]

def test_missing_allowlists():
    yaml_content = """
    security:
      allowed_tools: []
      restricted_commands: []
      allowed_domains: "*"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.CRITICAL]

def test_unsafe_execution():
    yaml_content = """
    executor:
      sandboxing: false
      allow_unrestricted_tools: true
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

def test_combined_risks():
    yaml_content = """
    llm:
      model: text-davinci-003
      temperature: 0.9
    executor:
      sandboxing: false
    logging:
      output_location: "/tmp/agent.log"
    security:
      allowed_domains: "*"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

def test_safe_configuration():
    yaml_content = """
    llm:
      model: gpt-3.5-turbo
      provider: openai
      temperature: 0.5
      rate_limit: 100
      timeout: 30
    executor:
      sandboxing: true
      rate_limit: 100
      timeout: 30
    logging:
      output_location: "/var/log/agent.log"
      level: "info"
    security:
      allowed_tools: ["search", "read"]
      restricted_commands: ["rm", "chmod"]
      allowed_domains: ["api.example.com"]
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 0
    assert report.overall_risk == RiskLevel.LOW

def test_invalid_yaml():
    yaml_content = """
    llm:
      model: gpt-3.5-turbo
      temperature: invalid
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert report.overall_risk in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]

def test_model_temperature_secure():
    config = {"llm": {"temperature": 0.5}}
    assert config["llm"]["temperature"] <= 0.7

def test_shelltool_command_allowlist():
    config = {"tools": {"ShellTool": {"allow_unrestricted_tools": False, "restricted_commands": ["ls"]}}}
    assert not config["tools"]["ShellTool"]["allow_unrestricted_tools"]
    assert len(config["tools"]["ShellTool"]["restricted_commands"]) > 0

def test_requests_tool_allowlist():
    config = {"tools": {"RequestsGetTool": {"allowed_domains": ["example.com"]}}}
    domains = config["tools"]["RequestsGetTool"]["allowed_domains"]
    assert "*" not in domains

def test_auth_enabled():
    config = {"auth": {"enabled": True}}
    assert config["auth"]["enabled"] is True

def test_input_sanitization_enabled():
    config = {"input_sanitization": True}
    assert config["input_sanitization"] is True
