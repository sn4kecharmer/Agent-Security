import json
from pathlib import Path

from agent_security.models import RiskLevel, SecurityReport
from agent_security.modern_checks import scan_modern_content
from agent_security.scanner import scan_file, scan_python_file


def report_for(path):
    return SecurityReport(
        findings=[],
        overall_risk=RiskLevel.LOW,
        file_path=str(path),
        timestamp="2026-01-01T00:00:00",
    )


def test_python_shell_true_and_dynamic_exec_are_reported(tmp_path):
    source = "import subprocess\nsubprocess.run(command, shell=True)\nexec(payload)\n"
    path = tmp_path / "agent.py"
    path.write_text(source, encoding="utf-8")

    result = scan_python_file(str(path), set(), tmp_path)
    names = {finding.pattern for finding in result.findings}

    assert "subprocess_shell_true" in names
    assert "dynamic_code_execution" in names
    assert result.overall_risk == RiskLevel.CRITICAL


def test_safe_subprocess_and_safe_yaml_loader_are_not_flagged(tmp_path):
    source = "import subprocess\nimport yaml\nsubprocess.run([\"echo\", \"ok\"])\nyaml.load(data, Loader=yaml.SafeLoader)\n"
    path = tmp_path / "safe.py"
    path.write_text(source, encoding="utf-8")

    result = scan_python_file(str(path), set(), tmp_path)
    names = {finding.pattern for finding in result.findings}

    assert "subprocess_shell_true" not in names
    assert "unsafe_yaml_load" not in names


def test_ast_checks_support_import_aliases_without_flagging_other_run_methods(tmp_path):
    source = "import subprocess as sp\nimport yaml as y\nfrom yaml import SafeLoader as Safe\nsp.run(command, shell=True)\ny.load(data, Loader=Safe)\n"
    path = tmp_path / "aliases.py"
    path.write_text(source, encoding="utf-8")
    result = scan_python_file(str(path), set(), tmp_path)
    names = {finding.pattern for finding in result.findings}
    assert "subprocess_shell_true" in names
    assert "unsafe_yaml_load" not in names

    unrelated = tmp_path / "unrelated.py"
    unrelated.write_text("runner.run(command, shell=True)\n", encoding="utf-8")
    other_result = scan_python_file(str(unrelated), set(), tmp_path)
    assert "subprocess_shell_true" not in {finding.pattern for finding in other_result.findings}


def test_unsafe_yaml_loader_is_reported(tmp_path):
    source = "import yaml\ndata = yaml.load(untrusted)\n"
    path = tmp_path / "unsafe.py"
    path.write_text(source, encoding="utf-8")

    result = scan_python_file(str(path), set(), tmp_path)
    assert "unsafe_yaml_load" in {finding.pattern for finding in result.findings}


def test_mcp_json_flags_shell_wrapper_http_and_wildcard(tmp_path):
    content = json.dumps(
        {
            "mcpServers": {
                "example": {
                    "command": "bash",
                    "args": ["-c", "node server.js"],
                    "url": "http://server.example/mcp",
                    "allowed_tools": ["*"],
                }
            }
        },
        indent=2,
    )
    path = tmp_path / "mcp.json"
    path.write_text(content, encoding="utf-8")

    result = scan_file(str(path), set(), tmp_path)
    names = {finding.pattern for finding in result.findings}

    assert "mcp_shell_wrapper" in names
    assert "mcp_insecure_http_transport" in names
    assert "mcp_wildcard_tool_scope" in names
    assert result.overall_risk == RiskLevel.CRITICAL


def test_hardcoded_secret_is_flagged_but_redacted(tmp_path):
    source = 'api_key = "a1b2c3d4e5f6g7h8i9j0"\neval(payload)\n'
    result = report_for(tmp_path / "agent.py")

    scan_modern_content(source, str(tmp_path / "agent.py"), result, set(), tmp_path, python_source=True)

    finding = next(f for f in result.findings if f.pattern == "hardcoded_credential")
    assert "a1b2c3d4e5f6g7h8i9j0" not in finding.context
    assert "[REDACTED]" in finding.context
    assert all("a1b2c3d4e5f6g7h8i9j0" not in (f.context or "") for f in result.findings)


def test_non_agent_json_is_ignored(tmp_path):
    path = tmp_path / "ordinary.json"
    path.write_text('{"message": "hello"}', encoding="utf-8")

    result = scan_file(str(path), set(), tmp_path)
    assert result.findings == []


def test_scan_file_rejects_sibling_path_sharing_base_prefix(tmp_path):
    base = tmp_path / "agent"
    sibling = tmp_path / "agent-other"
    base.mkdir()
    sibling.mkdir()
    target = sibling / "outside.py"
    target.write_text("print('outside')\n", encoding="utf-8")

    try:
        scan_file(str(target), set(), base)
    except ValueError as error:
        assert "outside the base directory" in str(error)
    else:
        raise AssertionError("scanner accepted a path outside its base directory")


def test_approval_bypass_configuration_is_flagged(tmp_path):
    content = "agent:\n  require_human_approval: false\n"
    result = report_for(tmp_path / "agent.yaml")

    scan_modern_content(content, str(tmp_path / "agent.yaml"), result, set(), tmp_path)

    finding = next(f for f in result.findings if f.pattern == "agent_approval_disabled")
    assert finding.risk_level == RiskLevel.HIGH


def test_yaml_shell_tool_rule_does_not_borrow_neighbor_enabled_flag(tmp_path):
    content = "tools:\n  - name: shell_tool\n    type: ShellTool\n    enabled: false\n  - name: another_tool\n    type: OtherTool\n    enabled: true\n"
    result = report_for(tmp_path / "agent.yaml")

    scan_modern_content(content, str(tmp_path / "agent.yaml"), result, set(), tmp_path)

    assert "yaml_enabled_shell_tool" not in {finding.pattern for finding in result.findings}
