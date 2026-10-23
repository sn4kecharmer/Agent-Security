"""Conservative v1.1 checks for current agent and MCP security risks.

These are static-analysis heuristics. They flag concrete risky constructs for
review; they do not prove exploitability or replace runtime authorization,
sandboxing, or human approval controls.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional, Set, Tuple

from .models import RiskLevel, SecurityFinding, SecurityInfo, SecurityReport


# Values are deliberately redacted in evidence and never copied into reports.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b[\w.-]*(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret)\b\s*[:=]\s*)(['\"])(.{8,}?)\2"
)
_PLACEHOLDER = re.compile(
    r"(?i)(?:your[_ -]?|example|sample|changeme|change[_ -]?me|placeholder|dummy|redacted|xxxxx|<[^>]+>|\$\{|getenv\(|environ\[|process\.env)"
)


def _rule(
    name: str,
    risk: RiskLevel,
    description: str,
    impact: str,
    remediation: str,
    category: str = "Agent Security",
    confidence: str = "Medium",
    owasp: Optional[list[str]] = None,
) -> SecurityInfo:
    return SecurityInfo(
        risk_level=risk,
        pattern=re.compile(r"."),
        description=description,
        impact=impact,
        remediation=remediation,
        category=category,
        confidence=confidence,
        cwe=[],
        owasp=owasp or [],
    )


_CONFIG_RULES = (
    (
        "mcp_shell_wrapper",
        re.compile(r"(?is)['\"]?command['\"]?\s*:\s*['\"](?:/bin/)?(?:ba|z|k)?sh['\"][^}]{0,800}?['\"]?args['\"]?\s*:\s*\[[^\]]{0,800}?['\"]-c['\"]"),
        _rule(
            "mcp_shell_wrapper",
            RiskLevel.CRITICAL,
            "MCP server is launched through a shell command string",
            "Shell-mediated server startup can turn configuration or argument injection into arbitrary command execution.",
            "Avoid shell wrappers and pass a fixed executable with separate arguments. Treat server configuration as executable code, review it, and run it with a least-privileged identity in an isolated environment.",
            "MCP Security",
            "High",
            ["OWASP MCP: Command Injection & Execution"],
        ),
    ),
    (
        "mcp_insecure_http_transport",
        re.compile(r"(?im)['\"]?(?:url|endpoint|server_url)['\"]?\s*:\s*['\"]?http://[^'\"\s,}]+"),
        _rule(
            "mcp_insecure_http_transport",
            RiskLevel.HIGH,
            "MCP endpoint uses unencrypted HTTP",
            "Credentials or tool traffic may be observed or modified in transit.",
            "Use HTTPS with certificate validation. Do not disable TLS verification to work around certificate errors.",
            "MCP Security",
            "High",
            ["OWASP MCP: Insufficient Authentication & Authorization"],
        ),
    ),
    (
        "mcp_wildcard_tool_scope",
        re.compile(r"(?im)['\"]?(?:allowed_tools|allowedTools|tool_allowlist|toolAllowlist)['\"]?\s*:\s*(?:['\"]\*['\"]|\[[^\]]{0,200}['\"]\*['\"]|\*)"),
        _rule(
            "mcp_wildcard_tool_scope",
            RiskLevel.HIGH,
            "MCP tool allow-list is a wildcard",
            "A wildcard can expose tools beyond the agent's intended task and magnify prompt-injection or tool-poisoning impact.",
            "Replace the wildcard with an explicit per-agent allow-list of the minimum required tools and enforce authorization outside the model.",
            "MCP Security",
            "Medium",
            ["OWASP MCP: Privilege Escalation via Scope Creep"],
        ),
    ),
    (
        "agent_approval_disabled",
        re.compile(r"(?im)['\"]?(?:require_human_approval|human_approval_required|approval_required|confirm_sensitive_actions)['\"]?\s*:\s*(?:false|no|0)\b"),
        _rule(
            "agent_approval_disabled",
            RiskLevel.HIGH,
            "Human approval is explicitly disabled",
            "Consequential tool actions may proceed without a user checking the exact operation and its target.",
            "Require explicit approval for high-impact actions such as sending, deleting, publishing, spending, deploying, or changing access. Enforce the approval check in the tool or downstream service, not only in the prompt.",
            "Agent Authorization",
            "Medium",
            ["OWASP LLM06:2025 Excessive Agency"],
        ),
    ),
    (
        "mcp_token_passthrough_enabled",
        re.compile(r"(?im)['\"]?(?:token_passthrough|pass_through_tokens|forward_client_token)['\"]?\s*:\s*(?:true|yes|1)\b"),
        _rule(
            "mcp_token_passthrough_enabled",
            RiskLevel.HIGH,
            "MCP token passthrough is enabled",
            "Forwarding client tokens without validating their issuer, audience, scope, and intended recipient can bypass downstream controls and audit boundaries.",
            "Do not pass through client tokens. Validate authorization for this server and acquire appropriately scoped downstream credentials. Bind identity and authorization to the requesting user and client.",
            "MCP Authorization",
            "High",
            ["OWASP MCP: Token Mismanagement & Secret Exposure"],
        ),
    ),
    (
        "yaml_enabled_shell_tool",
        re.compile(r"(?is)(?:type\s*:\s*['\"]?ShellTool['\"]?|name\s*:\s*['\"]?shell_tool['\"]?)(?:(?!\n[ \t]*-[ \t]*name:)[\s\S]){0,200}?enabled\s*:\s*true"),
        _rule("yaml_enabled_shell_tool", RiskLevel.CRITICAL, "Enabled ShellTool", "An enabled shell tool can execute commands with the agent process's operating-system privileges.", "Remove shell access unless essential. Prefer narrow task-specific tools; otherwise use an isolated, least-privileged environment with command allow-lists and timeouts.", "Tool Authorization", "High", ["OWASP LLM06:2025 Excessive Agency"]),
    ),
    (
        "yaml_browser_allow_all_hosts",
        re.compile(r"(?is)BrowserTool(?:(?!\n[ \t]*-[ \t]*name:)[\s\S]){0,250}?allow_all_hosts\s*:\s*true"),
        _rule("yaml_browser_allow_all_hosts", RiskLevel.HIGH, "BrowserTool with allow_all_hosts: true", "An agent-controlled browser can reach arbitrary hosts, increasing SSRF, internal service access, and data-exfiltration risk.", "Use an explicit domain allow-list and block loopback, private, link-local, and cloud metadata addresses after DNS resolution.", "Network Access", "High", ["OWASP MCP: Insufficient Authentication & Authorization"]),
    ),
    (
        "yaml_embedded_dynamic_execution",
        re.compile(r"(?i)\b(?:eval|exec)\s*\("),
        _rule("yaml_embedded_dynamic_execution", RiskLevel.CRITICAL, "Unsafe code execution", "Dynamic evaluation inside an agent configuration can execute attacker-controlled code with the host process's privileges.", "Remove dynamic evaluation. If execution is required, isolate it in a hardened sandbox with strict resource, network, and filesystem restrictions.", "Code Execution", "High", ["CWE-95"]),
    ),
)


def _redact_secrets(evidence: str) -> str:
    evidence = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]\2", evidence)
    # Avoid including long opaque tokens in nearby source context.
    return re.sub(r"(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,})\b", "[REDACTED]", evidence)


def _safe_evidence(lines: list[str], line_number: int) -> str:
    start = max(0, line_number - 2)
    end = min(len(lines), line_number + 1)
    return _redact_secrets("\n".join(lines[start:end]))


def _add_finding(
    report: SecurityReport,
    name: str,
    info: SecurityInfo,
    line_number: int,
    lines: list[str],
    file_path: str,
    ignored: Set[Tuple[str, int, str]],
    base_path: Path,
) -> None:
    finding = SecurityFinding(
        pattern=name,
        risk_level=info.risk_level,
        line_number=line_number,
        context=_safe_evidence(lines, line_number),
        security_info=info,
        file_path=file_path,
    )
    try:
        from .scanner import is_finding_ignored
        if Path(file_path).exists() and is_finding_ignored(finding, ignored, base_path):
            return
    except (ImportError, OSError, ValueError):
        pass
    if not any(f.pattern == name and f.line_number == line_number for f in report.findings):
        report.findings.append(finding)


def _ast_checks(
    source: str,
    file_path: str,
    report: SecurityReport,
    ignored: Set[Tuple[str, int, str]],
    base_path: Path,
) -> None:
    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError):
        return
    lines = source.splitlines()
    subprocess_modules = {"subprocess"}
    subprocess_functions: Set[str] = set()
    yaml_modules = {"yaml"}
    yaml_load_functions: Set[str] = set()
    safe_loader_names = {"SafeLoader", "CSafeLoader"}
    subprocess_methods = {"run", "Popen", "call", "check_call", "check_output"}
    for imported in ast.walk(tree):
        if isinstance(imported, ast.Import):
            for alias in imported.names:
                if alias.name == "subprocess":
                    subprocess_modules.add(alias.asname or "subprocess")
                elif alias.name == "yaml":
                    yaml_modules.add(alias.asname or "yaml")
        elif isinstance(imported, ast.ImportFrom):
            if imported.module == "subprocess":
                subprocess_functions.update(alias.asname or alias.name for alias in imported.names if alias.name in subprocess_methods)
            elif imported.module == "yaml":
                for alias in imported.names:
                    if alias.name == "load":
                        yaml_load_functions.add(alias.asname or alias.name)
                    elif alias.name in {"SafeLoader", "CSafeLoader"}:
                        safe_loader_names.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called_name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
        if called_name in {"eval", "exec"}:
            info = _rule(
                "dynamic_code_execution",
                RiskLevel.CRITICAL,
                "Dynamic Python code execution",
                "Evaluating generated or externally influenced code can execute arbitrary Python with the process's privileges.",
                "Remove eval/exec where possible. If code execution is an intended feature, isolate it in a hardened, resource-limited sandbox with a narrow API and no ambient credentials.",
                "Code Execution",
                "High",
                ["OWASP LLM06:2025 Excessive Agency"],
            )
            _add_finding(report, "dynamic_code_execution", info, node.lineno, lines, file_path, ignored, base_path)

        is_subprocess_call = (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in subprocess_modules
            and called_name in subprocess_methods
        ) or (isinstance(func, ast.Name) and func.id in subprocess_functions)
        if is_subprocess_call:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                info = _rule(
                    "subprocess_shell_true",
                    RiskLevel.CRITICAL,
                    "Subprocess uses shell=True",
                    "Shell parsing increases command-injection risk when any part of the command is influenced by a user, model, tool, or retrieved document.",
                    "Pass an argument list with shell=False. Validate each argument and constrain executable, environment, working directory, timeout, and OS privileges.",
                    "Command Injection",
                    "High",
                    ["OWASP MCP: Command Injection & Execution"],
                )
                _add_finding(report, "subprocess_shell_true", info, node.lineno, lines, file_path, ignored, base_path)

        is_yaml_load = (
            isinstance(func, ast.Attribute)
            and func.attr == "load"
            and isinstance(func.value, ast.Name)
            and func.value.id in yaml_modules
        ) or (isinstance(func, ast.Name) and func.id in yaml_load_functions)
        if is_yaml_load:
            loader = next((kw.value for kw in node.keywords if kw.arg in {"Loader", "loader"}), None)
            loader_name = loader.id if isinstance(loader, ast.Name) else loader.attr if isinstance(loader, ast.Attribute) else ""
            if loader_name not in safe_loader_names:
                info = _rule(
                    "unsafe_yaml_load",
                    RiskLevel.HIGH,
                    "YAML is loaded without an explicit safe loader",
                    "Unsafe YAML loading can instantiate objects or execute code when the document is attacker-controlled.",
                    "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). Never parse untrusted YAML with an unsafe loader.",
                    "Unsafe Deserialization",
                    "High",
                    ["CWE-502"],
                )
                _add_finding(report, "unsafe_yaml_load", info, node.lineno, lines, file_path, ignored, base_path)


def scan_modern_content(
    content: str,
    file_path: str,
    report: SecurityReport,
    ignored: Optional[Set[Tuple[str, int, str]]] = None,
    base_path: Optional[Path] = None,
    python_source: bool = False,
) -> SecurityReport:
    """Append targeted v1.1 findings to a normal scanner report."""
    ignored = ignored or set()
    base_path = base_path or Path(file_path).resolve().parent
    lines = content.splitlines()
    if python_source:
        _ast_checks(content, file_path, report, ignored, base_path)

    for match in _SECRET_ASSIGNMENT.finditer(content):
        value = match.group(3)
        if _PLACEHOLDER.search(value) or len(value.strip()) < 8:
            continue
        line_number = content.count("\n", 0, match.start()) + 1
        info = _rule(
            "hardcoded_credential",
            RiskLevel.HIGH,
            "Possible hardcoded credential",
            "A committed credential can be copied into source history, logs, build artifacts, or downstream agent context.",
            "Remove the credential from source, rotate it if it was real, and load secrets from a managed secret store or environment injection. The finding evidence is redacted.",
            "Secrets Management",
            "Medium",
            ["CWE-798"],
        )
        _add_finding(report, "hardcoded_credential", info, line_number, lines, file_path, ignored, base_path)

    is_mcp_config = Path(file_path).name.lower() in {"mcp.json", "mcp_config.json", "mcp_servers.json"} or bool(
        re.search(r"(?i)['\"]mcpServers['\"]\s*:", content)
    )
    if is_mcp_config or Path(file_path).suffix.lower() in {".json", ".yaml", ".yml"}:
        for name, pattern, info in _CONFIG_RULES:
            if name.startswith("mcp_") and not is_mcp_config:
                continue
            for match in pattern.finditer(content):
                line_number = content.count("\n", 0, match.start()) + 1
                _add_finding(report, name, info, line_number, lines, file_path, ignored, base_path)

    for finding in report.findings:
        if finding.context:
            finding.context = _redact_secrets(finding.context)

    if report.findings:
        report.overall_risk = max([report.overall_risk] + [finding.risk_level for finding in report.findings])
    return report
