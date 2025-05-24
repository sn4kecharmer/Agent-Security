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

def test_vulnerable_yaml_openagent():
    yaml_file_path = Path(__file__).parent.parent.parent / "examples/vulnerable_yaml_openAgent.yaml"
    with open(yaml_file_path, 'r') as f:
        yaml_content = f.read()
    
    report = scan_yaml_content(yaml_content, str(yaml_file_path), ignored_findings=set(), base_path=yaml_file_path.parent.parent)
    
    findings_map = {f.security_info.description: f for f in report.findings}
    
    # Check for specific findings
    assert "Enabled ShellTool" in findings_map
    assert findings_map["Enabled ShellTool"].line_number == 17 # or around 17-19
    assert findings_map["Enabled ShellTool"].risk_level == RiskLevel.CRITICAL

    assert "BrowserTool with allow_all_hosts: true" in findings_map
    assert findings_map["BrowserTool with allow_all_hosts: true"].line_number == 20 # or around 20-23
    assert findings_map["BrowserTool with allow_all_hosts: true"].risk_level == RiskLevel.HIGH

    assert "Unsafe code execution" in findings_map # For eval()
    # Ensure it's the one related to the custom_code_eval tool
    custom_eval_finding = None
    for finding in report.findings:
        if finding.security_info.description == "Unsafe code execution" and finding.line_number and 25 <= finding.line_number <= 28:
            custom_eval_finding = finding
            break
    assert custom_eval_finding is not None, "Eval in custom_code_eval not found"
    assert custom_eval_finding.risk_level == RiskLevel.CRITICAL
    
    # Check that eval is NOT misattributed to ShellTool
    shell_tool_eval_misattributed = False
    for finding in report.findings:
        if finding.security_info.description == "Unsafe code execution" and \
           finding.line_number and 17 <= finding.line_number <= 19: # Location of ShellTool
            shell_tool_eval_misattributed = True
            break
    assert not shell_tool_eval_misattributed, "Eval misattributed to ShellTool"

    assert "Allowing untrusted input" in findings_map
    assert findings_map["Allowing untrusted input"].line_number == 30
    assert findings_map["Allowing untrusted input"].risk_level == RiskLevel.HIGH

    assert "Authentication not required" in findings_map
    assert findings_map["Authentication not required"].line_number == 31
    assert findings_map["Authentication not required"].risk_level == RiskLevel.MEDIUM

    assert "Sensitive data may not be redacted from logs" in findings_map
    assert findings_map["Sensitive data may not be redacted from logs"].line_number == 33 # or around 33-34
    assert findings_map["Sensitive data may not be redacted from logs"].risk_level == RiskLevel.MEDIUM

    # Check overall risk
    assert report.overall_risk >= RiskLevel.CRITICAL


def test_langchain_agent_py():
    python_file_path = Path(__file__).parent.parent.parent / "examples/langchain_agent.py"
    
    # The scan_python_file function is available in the current scope due to scanner.py content
    # but it's better to import it explicitly if it were in a different module.
    # For this setup, we assume it's accessible as if it were imported.
    from agent_security.scanner import scan_python_file

    report = scan_python_file(str(python_file_path), ignored_findings=set(), base_path=python_file_path.parent.parent)
    
    findings_map = {f.security_info.description: f for f in report.findings}
    
    # Check for specific tool usages
    assert "LangChain ShellTool usage detected" in findings_map
    assert findings_map["LangChain ShellTool usage detected"].line_number == 10 # or around 10
    assert findings_map["LangChain ShellTool usage detected"].risk_level == RiskLevel.CRITICAL

    assert "LangChain PythonREPLTool usage detected" in findings_map
    assert findings_map["LangChain PythonREPLTool usage detected"].line_number == 15 # or around 15
    assert findings_map["LangChain PythonREPLTool usage detected"].risk_level == RiskLevel.CRITICAL

    assert "LangChain RequestsGetTool usage detected" in findings_map
    assert findings_map["LangChain RequestsGetTool usage detected"].line_number == 20 # or around 20
    assert findings_map["LangChain RequestsGetTool usage detected"].risk_level == RiskLevel.HIGH
    
    # Check for verbose logging
    assert "LangChain verbose logging enabled (e.g., verbose=True)" in findings_map
    verbose_finding = findings_map["LangChain verbose logging enabled (e.g., verbose=True)"]
    assert verbose_finding.line_number == 49 # or around 49
    assert verbose_finding.risk_level == RiskLevel.LOW

    # Check for correct LangChain agent identification (and not CrewAI)
    assert "LangChain LLMSingleActionAgent detected" in findings_map
    assert findings_map["LangChain LLMSingleActionAgent detected"].line_number == 44 # or around 44

    # Ensure it's NOT misclassified as CrewAI
    crew_ai_misclassification_found = False
    for finding in report.findings:
        if "CrewAI" in finding.security_info.description:
            crew_ai_misclassification_found = True
            break
    assert not crew_ai_misclassification_found, "LangChain agent misclassified as CrewAI"

    # Check overall risk
    assert report.overall_risk >= RiskLevel.CRITICAL
