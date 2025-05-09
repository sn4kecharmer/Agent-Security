import pytest
from agent_security.scanner import scan_yaml_content
from agent_security.models import RiskLevel
from pathlib import Path

def test_risky_llm_models():
    yaml_content = """
    llm:
      model: text-davinci-003
      temperature: 0.8
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 4
    assert any(f.pattern == "risky_llm_model" for f in report.findings)
    assert any(f.pattern == "high_temperature" for f in report.findings)
    assert any(f.pattern == "missing_llm_provider" for f in report.findings)
    assert any(f.pattern == "missing_rate_limits" for f in report.findings)
    assert report.overall_risk == RiskLevel.HIGH

def test_missing_llm_provider():
    yaml_content = """
    llm:
      model: gpt-3.5-turbo
      temperature: 0.5
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 2
    assert any(f.pattern == "missing_llm_provider" for f in report.findings)
    assert any(f.pattern == "missing_rate_limits" for f in report.findings)
    assert report.overall_risk == RiskLevel.HIGH

def test_prompt_injection_surfaces():
    yaml_content = """
    agent:
      prompt: "Execute {input} with {tools}"
      template: "Use {agent_scratchpad} to process"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 2
    assert all(f.pattern == "unsafe_prompt_template" for f in report.findings)
    assert report.overall_risk == RiskLevel.HIGH

def test_risky_tool_descriptions():
    yaml_content = """
    tools:
      - name: shell
        description: "Execute arbitrary shell commands"
      - name: file
        description: "Full access to file system"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 4
    assert sum(1 for f in report.findings if f.pattern == "risky_tool_description") == 2
    assert sum(1 for f in report.findings if f.pattern == "missing_rate_limits") == 2
    assert report.overall_risk == RiskLevel.HIGH

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
    assert len(report.findings) == 4
    assert sum(1 for f in report.findings if f.pattern == "missing_rate_limits") == 3
    assert sum(1 for f in report.findings if f.pattern == "missing_llm_provider") == 1
    assert report.overall_risk == RiskLevel.HIGH

def test_unsafe_logging():
    yaml_content = """
    logging:
      output_location: "/tmp/agent.log"
      level: "debug"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 2
    assert all(f.pattern == "unsafe_logging" for f in report.findings)
    assert report.overall_risk == RiskLevel.MEDIUM

def test_missing_allowlists():
    yaml_content = """
    security:
      allowed_tools: []
      restricted_commands: []
      allowed_domains: "*"
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 3
    assert all(f.pattern == "missing_allowlist" for f in report.findings)
    assert report.overall_risk == RiskLevel.HIGH

def test_unsafe_execution():
    yaml_content = """
    executor:
      sandboxing: false
      allow_unrestricted_tools: true
    """
    report = scan_yaml_content(yaml_content, "test.yaml", ignored_findings=set(), base_path=Path('.'))
    assert len(report.findings) == 3
    assert sum(1 for f in report.findings if f.pattern == "missing_rate_limits") == 1
    assert sum(1 for f in report.findings if f.pattern == "unsafe_execution") == 2
    assert report.overall_risk == RiskLevel.CRITICAL

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
    assert len(report.findings) == 8
    assert sum(1 for f in report.findings if f.pattern == "risky_llm_model") == 1
    assert sum(1 for f in report.findings if f.pattern == "high_temperature") == 1
    assert sum(1 for f in report.findings if f.pattern == "missing_llm_provider") == 1
    assert sum(1 for f in report.findings if f.pattern == "missing_rate_limits") == 2
    assert sum(1 for f in report.findings if f.pattern == "unsafe_execution") == 1
    assert sum(1 for f in report.findings if f.pattern == "unsafe_logging") == 1
    assert sum(1 for f in report.findings if f.pattern == "missing_allowlist") == 1
    assert report.overall_risk == RiskLevel.CRITICAL

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
    assert len(report.findings) == 2
    assert any(f.pattern == "missing_llm_provider" for f in report.findings)
    assert any(f.pattern == "missing_rate_limits" for f in report.findings)
    assert report.overall_risk == RiskLevel.HIGH 

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
