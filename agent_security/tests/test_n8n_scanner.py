import pytest
import json
from pathlib import Path
from typing import Set, Tuple, List

from agent_security.n8n_scanner import scan_n8n_workflow_content
from agent_security.models import RiskLevel, SecurityFinding, SecurityReport

# Define a base path for fixtures, assuming tests are run from the project root
# or that paths are adjusted accordingly. For now, let's assume tests are run
# such that this relative path works.
FIXTURES_BASE_PATH = Path(__file__).parent / "fixtures"
SCANNER_BASE_PATH = Path(__file__).parent.parent # agent_security directory

# Mock ignored_findings for scanner function, typically an empty set for these tests
NO_IGNORED_FINDINGS: Set[Tuple[str, int, str]] = set()

def load_fixture(filename: str) -> str:
    """Loads a fixture file content."""
    with open(FIXTURES_BASE_PATH / filename, 'r') as f:
        return f.read()

def assert_finding(finding: SecurityFinding, expected_pattern: str, expected_risk: RiskLevel, expected_line: int = None):
    """Helper to assert common finding attributes."""
    assert finding.pattern == expected_pattern
    assert finding.risk_level == expected_risk
    if expected_line is not None:
        # Line number matching can be tricky with JSON and heuristics.
        # Be somewhat flexible or ensure fixtures + scanner are consistent.
        assert finding.line_number == expected_line, f"Expected line {expected_line}, got {finding.line_number} for {finding.pattern}"

# 1. Test for a safe n8n workflow
def test_scan_safe_n8n_workflow():
    content = load_fixture("n8n_safe_workflow.json")
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_safe_workflow.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    assert len(report.findings) == 0
    assert report.overall_risk == RiskLevel.LOW

# 2. Test for Code node with process.env access
def test_scan_n8n_code_env_access():
    content = load_fixture("n8n_code_env_access.json")
    # Line number estimation for "id": "code-node-env" in n8n_code_env_access.json
    # "name": "Access Env Var", (line 15) ... "id": "code-node-env" (line 20)
    # The scanner looks for id first, then name.
    # If "id": "code-node-env" is on line 20 (1-indexed).
    expected_line = 20 
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_code_env_access.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    assert len(report.findings) == 1
    assert_finding(report.findings[0], "n8n_code_node_env_access", RiskLevel.HIGH, expected_line)
    assert "process.env" in report.findings[0].context

# 3. Test for Code node with eval()
def test_scan_n8n_code_eval():
    content = load_fixture("n8n_code_eval.json")
    # "id": "code-node-eval" (line 20)
    expected_line = 20
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_code_eval.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    assert len(report.findings) == 1
    assert_finding(report.findings[0], "n8n_code_node_eval_usage", RiskLevel.CRITICAL, expected_line)
    assert "eval(" in report.findings[0].context

# 4. Test for Code node with new Function()
def test_scan_n8n_code_new_function():
    content = load_fixture("n8n_code_new_function.json")
    # "id": "code-node-new-func" (line 20)
    expected_line = 20
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_code_new_function.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    assert len(report.findings) == 1
    assert_finding(report.findings[0], "n8n_code_node_eval_usage", RiskLevel.CRITICAL, expected_line) # Uses the same pattern name
    assert "new Function(" in report.findings[0].context

# 5. Test for Code node with setTimeout('...')
def test_scan_n8n_code_settimeout_string():
    content = load_fixture("n8n_code_settimeout_string.json")
    # "id": "code-node-settimeout" (line 20)
    expected_line = 20
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_code_settimeout_string.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    assert len(report.findings) == 1
    assert_finding(report.findings[0], "n8n_code_node_eval_usage", RiskLevel.CRITICAL, expected_line) # Uses the same pattern name
    assert "setTimeout('" in report.findings[0].context

# 6. Test for Execute Command node (general usage)
def test_scan_n8n_exec_command_usage():
    content = load_fixture("n8n_exec_command_usage.json")
    # "id": "exec-node-basic" (line 18)
    expected_line = 18 
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_exec_command_usage.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    
    # This will generate TWO findings:
    # 1. n8n_execute_command_node_usage (because the node type is used)
    # 2. Potentially n8n_hardcoded_api_key_generic if "echo 'Hello World'" matches (unlikely with current regex)
    #    The current hardcoded secret regex looks for keywords like api_key, secret, etc. "echo 'Hello World'" won't match.
    
    assert len(report.findings) == 1
    assert_finding(report.findings[0], "n8n_execute_command_node_usage", RiskLevel.HIGH, expected_line)
    assert "Execute Command Node 'Execute Echo' is used" in report.findings[0].context

# 7. Test for Execute Command node with an n8n expression
def test_scan_n8n_exec_command_expression():
    content = load_fixture("n8n_exec_command_expression.json")
    # "id": "exec-node-expr" (line 18)
    expected_line = 18
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_exec_command_expression.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    
    # Expect two findings:
    # 1. n8n_execute_command_node_usage (HIGH) - for using the node
    # 2. n8n_command_injection_execute_command (CRITICAL) - for expression in command
    
    assert len(report.findings) == 2
    found_usage = False
    found_injection = False
    for finding in report.findings:
        if finding.pattern == "n8n_execute_command_node_usage":
            assert_finding(finding, "n8n_execute_command_node_usage", RiskLevel.HIGH, expected_line)
            assert "Execute Command Node 'Execute Dynamic Echo' is used" in finding.context
            found_usage = True
        elif finding.pattern == "n8n_command_injection_execute_command":
            assert_finding(finding, "n8n_command_injection_execute_command", RiskLevel.CRITICAL, expected_line)
            assert "parameter 'command' uses an n8n expression" in finding.security_info.description # Check new pattern's desc
            assert "{{ $json.data }}" in finding.context
            found_injection = True
            
    assert found_usage and found_injection
    assert report.overall_risk == RiskLevel.CRITICAL

# 8. Test for hardcoded API key
def test_scan_n8n_hardcoded_secret():
    content = load_fixture("n8n_hardcoded_secret.json")
    # "id": "http-node-secret" (line 31)
    expected_line = 31
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_hardcoded_secret.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    
    # Expect two findings for "n8n_hardcoded_api_key_generic"
    # One for "value": "sk_live_abcdefghijklmnopqrstuvwxyz1234567890"
    # One for "value": "password1234567890abcdefghijklmnop"
    
    assert len(report.findings) == 2
    found_sk_live = False
    found_password = False

    for finding in report.findings:
        assert finding.pattern == "n8n_hardcoded_api_key_generic"
        assert finding.risk_level == RiskLevel.HIGH
        assert finding.line_number == expected_line # Both are parameters of the same node
        if "sk_live_abcdefghijklmnopqrstuvwxyz1234567890" in finding.context:
            found_sk_live = True
        if "password1234567890abcdefghijklmnop" in finding.context:
            found_password = True
            
    assert found_sk_live
    assert found_password
    assert report.overall_risk == RiskLevel.HIGH

# 9. Test for HTTP Request node with n8n expression in URL
def test_scan_n8n_http_url_expression():
    content = load_fixture("n8n_http_url_expression.json")
    # "id": "http-node-url-expr" (line 19)
    expected_line = 19
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_http_url_expression.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    assert len(report.findings) == 1
    assert_finding(report.findings[0], "n8n_sensitive_data_in_http_url", RiskLevel.HIGH, expected_line)
    assert "URL contains an n8n expression" in report.findings[0].context
    assert "https://api.example.com/users/{{ $json.userId }}" in report.findings[0].context

# 10. Test for HTTP Request node with potential SSRF
def test_scan_n8n_http_ssrf():
    content = load_fixture("n8n_http_ssrf.json")
    # "id": "http-node-ssrf" (line 19)
    expected_line = 19
    report = scan_n8n_workflow_content(content, str(FIXTURES_BASE_PATH / "n8n_http_ssrf.json"), NO_IGNORED_FINDINGS, SCANNER_BASE_PATH)
    
    # This might also trigger n8n_sensitive_data_in_http_url if the URL itself is an expression.
    # In this case, it's a hardcoded SSRF-like URL.
    # The n8n_sensitive_data_in_http_url pattern looks for {{...}}, which "http://localhost:5000" doesn't have.
    # So only n8n_ssrf_http_request_node should trigger.
    
    assert len(report.findings) == 1
    assert_finding(report.findings[0], "n8n_ssrf_http_request_node", RiskLevel.HIGH, expected_line)
    assert "localhost" in report.findings[0].context
    assert "http://localhost:5000/internal/data" in report.findings[0].context

# Helper to verify line numbers in fixtures to reduce errors in tests
# This is a manual check for now.
# To run this: add a call to it in any test or a dedicated one.
def _print_fixture_line_numbers():
    files = [
        "n8n_code_env_access.json", "n8n_code_eval.json", "n8n_code_new_function.json",
        "n8n_code_settimeout_string.json", "n8n_exec_command_usage.json",
        "n8n_exec_command_expression.json", "n8n_hardcoded_secret.json",
        "n8n_http_url_expression.json", "n8n_http_ssrf.json"
    ]
    for filename in files:
        print(f"\n--- {filename} ---")
        content = load_fixture(filename)
        data = json.loads(content)
        lines = content.splitlines()
        for node in data.get("nodes", []):
            node_id = node.get("id")
            node_name = node.get("name")
            id_line = -1
            name_line = -1
            for i, line_text in enumerate(lines):
                if f'"id": "{node_id}"' in line_text:
                    id_line = i + 1
                if f'"name": "{node_name}"' in line_text:
                    name_line = i + 1
            print(f"Node '{node_name}' (ID: {node_id}): Name line ~{name_line}, ID line ~{id_line}")

# Example of how to run the line number printer:
# if __name__ == "__main__":
# _print_fixture_line_numbers()

# Line number verification:
# --- n8n_code_env_access.json ---
# Node 'Access Env Var' (ID: code-node-env): Name line ~15, ID line ~20
# --- n8n_code_eval.json ---
# Node 'Use Eval' (ID: code-node-eval): Name line ~15, ID line ~20
# --- n8n_code_new_function.json ---
# Node 'Use New Function' (ID: code-node-new-func): Name line ~15, ID line ~20
# --- n8n_code_settimeout_string.json ---
# Node 'Use SetTimeout String' (ID: code-node-settimeout): Name line ~15, ID line ~20
# --- n8n_exec_command_usage.json ---
# Node 'Execute Echo' (ID: exec-node-basic): Name line ~14, ID line ~18
# --- n8n_exec_command_expression.json ---
# Node 'Execute Dynamic Echo' (ID: exec-node-expr): Name line ~14, ID line ~18
# --- n8n_hardcoded_secret.json ---
# Node 'HTTP Request with Secret' (ID: http-node-secret): Name line ~24, ID line ~31
# --- n8n_http_url_expression.json ---
# Node 'HTTP Request with URL Expression' (ID: http-node-url-expr): Name line ~15, ID line ~19
# --- n8n_http_ssrf.json ---
# Node 'HTTP Request with SSRF URL' (ID: http-node-ssrf): Name line ~15, ID line ~19

# The line numbers in the tests above have been set based on these manual checks.
# The scanner's heuristic is: "if node_id: search for id line, else search for name line".
# My line numbers above are for the line containing the `id` field if present.
# For test_scan_n8n_exec_command_expression:
# The description for n8n_command_injection_execute_command pattern is:
# "The 'command' parameter of an Execute Command node uses an n8n expression..."
# I should check this in the assertion.

# For test_scan_n8n_hardcoded_secret:
# The pattern `n8n_hardcoded_api_key_generic` is applied to all string parameters.
# The first secret is in `parameters.options.auth.value`
# The second secret is in `parameters.bodyParameters.parameters[0].value`
# Both are part of the node with id "http-node-secret" (line 31).
# The scanner reports the line of the node for findings in its parameters. This is consistent.

# Modification for test_scan_n8n_exec_command_expression assertion:
# `assert "parameter 'command' uses an n8n expression" in finding.security_info.description`
# The `security_info.description` for `n8n_command_injection_execute_command` is:
# "The 'command' parameter of an Execute Command node uses an n8n expression (e.g., {{ $json.body.command }})."
# This should match.

# Final check of context for test_scan_n8n_exec_command_usage
# The context for n8n_execute_command_node_usage is:
# `f"Execute Command Node '{node_name}' is used."`
# If command_str: `context_exec += f"\nCommand: {textwrap.shorten(str(command_str), width=150, placeholder='...')}"`
# So, `assert "Execute Command Node 'Execute Echo' is used" in report.findings[0].context` is correct.
# And for the expression one: `assert "Execute Command Node 'Execute Dynamic Echo' is used" in finding.context`
# And `assert "{{ $json.data }}" in finding.context` (this checks the command part of the context).

# Looks good.The test file `agent_security/tests/test_n8n_scanner.py` has been created with 10 test cases covering the specified scenarios. Fixture files were used to provide n8n workflow JSON content. Assertions check for the number of findings, pattern names, risk levels, and heuristic-based line numbers. Context strings are also checked for relevant information.

Line numbers were manually verified against the fixture files to align with the scanner's current line detection heuristic.

The tests are structured as:
1.  `test_scan_safe_n8n_workflow`: Checks a safe workflow, expecting 0 findings.
2.  `test_scan_n8n_code_env_access`: Checks for `process.env` access, expects 1 finding (`n8n_code_node_env_access`).
3.  `test_scan_n8n_code_eval`: Checks for `eval()`, expects 1 finding (`n8n_code_node_eval_usage`).
4.  `test_scan_n8n_code_new_function`: Checks for `new Function()`, expects 1 finding (`n8n_code_node_eval_usage`).
5.  `test_scan_n8n_code_settimeout_string`: Checks for `setTimeout` with a string, expects 1 finding (`n8n_code_node_eval_usage`).
6.  `test_scan_n8n_exec_command_usage`: Checks for general Execute Command node usage, expects 1 finding (`n8n_execute_command_node_usage`).
7.  `test_scan_n8n_exec_command_expression`: Checks for Execute Command node with an expression in the command, expects 2 findings (`n8n_execute_command_node_usage` and `n8n_command_injection_execute_command`).
8.  `test_scan_n8n_hardcoded_secret`: Checks for hardcoded secrets in node parameters, expects 2 findings (`n8n_hardcoded_api_key_generic`).
9.  `test_scan_n8n_http_url_expression`: Checks for HTTP Request node with an expression in the URL, expects 1 finding (`n8n_sensitive_data_in_http_url`).
10. `test_scan_n8n_http_ssrf`: Checks for HTTP Request node with a potential SSRF URL, expects 1 finding (`n8n_ssrf_http_request_node`).

A helper function `assert_finding` was created to reduce boilerplate in assertions.
The line numbers for assertions were determined by inspecting the fixture files and the scanner's logic for identifying the line of a node (based on `id` or `name`).

The tests seem complete and cover all requirements of the subtask.
