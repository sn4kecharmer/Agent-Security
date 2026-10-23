"""
Security patterns for the agent security scanner.
"""

from .agent_patterns import AGENT_PATTERNS
from .framework_patterns import FRAMEWORK_PATTERNS
from .environment_patterns import ENVIRONMENT_PATTERNS
from .tool_patterns import TOOL_PATTERNS
from ..models import SecurityInfo, RiskLevel
import re

__all__ = [
    'AGENT_PATTERNS',
    'FRAMEWORK_PATTERNS',
    'ENVIRONMENT_PATTERNS',
    'TOOL_PATTERNS',
    'TOOL_RISKS',
    'YAML_TOOL_PATTERNS',
    'ACTION_RISK_DESCRIPTIONS'
]

# Tool risk patterns
TOOL_RISKS = {
    "langchain": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"from\s+langchain\s+import|import\s+langchain"),
        description="LangChain usage detected",
        impact="Potential security risks from LangChain's extensive capabilities",
        remediation="Ensure proper security controls and validation for LangChain tools"
    ),
    "path_traversal": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"os\.path\.join\([^)]*['\"][^'\"]*['\"][^)]*\)|open\([^)]*\.\.[^)]*\)"),
        description="Potential path traversal vulnerability",
        impact="Could allow access to files outside intended directory",
        remediation="Validate and sanitize file paths, use path sanitization libraries"
    ),
    "redos": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"pattern\s*=\s*r?['\"].*\(\w+\+\)\+"),
        description="Potential ReDoS vulnerability",
        impact="Could allow denial of service through regex",
        remediation="Use safe regex patterns, implement timeouts"
    ),
    "insecure_storage": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"def\s+store_password.*\n.*open\(['\"].*['\"],\s*['\"]w['\"]\).*\n.*\.write\("),
        description="Insecure credential storage",
        impact="Credentials stored in plaintext",
        remediation="Use secure credential storage solutions"
    ),
    "crewai_memory": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"from\s+crewai\.memory\s+import|import\s+crewai\.memory"),
        description="CrewAI memory usage detected",
        impact="Potential data persistence and memory manipulation risks",
        remediation="Use ephemeral memory and implement proper memory sanitization"
    ),
    "crewai_agent": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"Agent\s*\([^)]*(?:role|goal)\s*="),
        description="CrewAI agent creation detected",
        impact="Potential security risks from agent capabilities",
        remediation="Implement proper security controls and validation for agent actions"
    ),
    "crewai_task": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"Task\("),
        description="CrewAI task creation detected",
        impact="Potential security risks from task execution",
        remediation="Validate task inputs and outputs, implement proper error handling"
    ),
    "crewai_autonomous": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\.kickoff\(|\.process\(|\.run\("),
        description="CrewAI autonomous execution detected",
        impact="Potential security risks from autonomous agent execution",
        remediation="Implement proper monitoring and control mechanisms"
    ),
    "eval_exec": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"eval\(|exec\("),
        description="Unsafe code execution detected",
        impact="Arbitrary code execution vulnerability",
        remediation="Remove eval/exec usage, use safe alternatives, implement input validation"
    ),
    "unrestricted_file_access": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"open\(.*\)\.read\(\)"),
        description="Unrestricted file access detected",
        impact="File system access vulnerability",
        remediation="Implement proper file access validation and sanitization"
    ),
    "command_injection": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"subprocess\.(?:call|run|Popen)|os\.system|shell\s*=\s*True"),
        description="Command injection vulnerability",
        impact="Could allow arbitrary command execution",
        remediation="Use safe command execution methods, validate and sanitize inputs"
    ),
    "hardcoded_secrets": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"(?:password|secret|token|key|api_key|api[_-]token|auth[_-]token|access[_-]token|secret[_-]key|client[_-]secret)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        description="Hardcoded secrets detected",
        impact="Secrets exposed in source code",
        remediation="Use environment variables or secure secret management"
    ),
    "insecure_temp": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"tempfile\.(?:mktemp|NamedTemporaryFile)|/tmp/"),
        description="Insecure temporary file usage",
        impact="Could lead to race conditions or information disclosure",
        remediation="Use secure temporary file creation methods"
    ),
    "unsafe_file_perms": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"chmod\s+777|os\.chmod.*0o777|st_mode.*0o777"),
        description="Unsafe file permissions",
        impact="Could allow unauthorized access to files",
        remediation="Use minimal necessary permissions"
    ),
    "unrestricted_web": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"requests\.(?:get|post|put|delete)|urllib\.request\.urlopen"),
        description="Unrestricted web access",
        impact="Could allow unauthorized API calls or data exfiltration",
        remediation="Implement proper URL validation and request limits"
    )
}

# YAML tool patterns
YAML_TOOL_PATTERNS = {
    "risky_tool_description": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"description:\s*[\"']?(?:arbitrary|any|unrestricted|full access|Execute any command)[\"']?", re.IGNORECASE),
        description="Risky tool description detected",
        impact="Potential security risks from unrestricted tool capabilities",
        remediation="Use specific, limited tool descriptions and implement proper validation"
    ),
    "unsafe_tool_config": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_all:\s*true|validate:\s*false|validation:\s*false|allow_unrestricted_tools:\s*true|restricted_commands:\s*\[\]|sandboxing:\s*false|rate_limit:\s*null|auth:\s*\n\s+enabled:\s*false|input_sanitization:\s*false", re.IGNORECASE),
        description="Unsafe tool configuration detected",
        impact="Potential security risks from disabled validation and security controls",
        remediation="Enable validation, sandboxing, rate limiting, and authentication"
    ),
    "unsafe_execution": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"mode:\s*unrestricted|validation:\s*false|monitoring:\s*false|log_level:\s*debug|verbose:\s*true", re.IGNORECASE),
        description="Unsafe execution configuration detected",
        impact="Potential security risks from unrestricted execution and excessive logging",
        remediation="Enable validation and monitoring, implement proper security controls"
    ),
    "shell_tool": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"name:\s*ShellTool", re.MULTILINE),
        description="Shell command execution tool enabled",
        impact="Allows execution of arbitrary shell commands, which could lead to system compromise",
        remediation="Disable shell command execution or strictly limit allowed commands using an allowlist"
    ),
    "python_repl_tool": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"name:\s*PythonREPLTool", re.MULTILINE),
        description="Python REPL tool enabled",
        impact="Allows execution of arbitrary Python code, which could lead to system compromise",
        remediation="Disable Python REPL or use a sandboxed environment with restricted capabilities"
    ),
    "unrestricted_web_access": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"name:\s*RequestsGetTool|allowed_domains:\s*\[\"\*\"\]", re.MULTILINE),
        description="Unrestricted web access enabled",
        impact="Allows unrestricted web requests which could lead to SSRF or data exfiltration",
        remediation="Implement URL allowlisting and proper request validation"
    ),
    "memory_manipulation": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"memory:\s*\n\s+type:\s*[\"']?conversation[\"']?", re.MULTILINE),
        description="Conversation memory enabled",
        impact="Agent can retain and potentially manipulate conversation history",
        remediation="Use ephemeral memory or implement proper memory sanitization"
    ),
    "execute_shell_commands": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"description:\s*[\"']?Execute shell commands[\"']?", re.MULTILINE),
        description="Shell command execution capability",
        impact="Tool can execute arbitrary shell commands, which could lead to system compromise",
        remediation="Remove shell command execution capability or strictly limit allowed commands"
    ),
    "execute_python_code": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"description:\s*[\"']?Execute Python code[\"']?", re.MULTILINE),
        description="Python code execution capability",
        impact="Tool can execute arbitrary Python code, which could lead to system compromise",
        remediation="Remove Python code execution capability or use a sandboxed environment"
    ),
    "unsafe_model_config": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"temperature:\s*0\.9|provider:\s*text-davinci-003", re.MULTILINE),
        description="Unsafe model configuration",
        impact="High temperature and powerful model could lead to unpredictable behavior",
        remediation="Use lower temperature and more restricted models"
    ),
    "unsafe_output_handling": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"output_location:\s*/tmp/|save_outputs:\s*true", re.MULTILINE),
        description="Unsafe output handling",
        impact="Saving outputs to unprotected locations could lead to data leakage",
        remediation="Use secure output locations and implement proper output sanitization"
    ),
    "high_temperature": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"temperature:\s*(?:0\.[89]|1\.0)", re.IGNORECASE),
        description="High model temperature",
        impact="Could lead to unpredictable or unsafe outputs",
        remediation="Use lower temperature values for better control"
    ),
    "no_auth": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"auth:\s*(?:false|disabled|off)|authentication:\s*(?:false|disabled|off)", re.IGNORECASE),
        description="Authentication disabled",
        impact="Could allow unauthorized access",
        remediation="Enable authentication and implement proper access controls"
    ),
    "no_sandbox": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"sandbox:\s*(?:false|disabled|off)|sandboxing:\s*(?:false|disabled|off)", re.IGNORECASE),
        description="Sandboxing disabled",
        impact="Could allow unsafe code execution",
        remediation="Enable sandboxing for code execution"
    ),
    "permissive_tools": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"(?:allow_all_tools:\s*true|unrestricted_tools:\s*true|tool_access:\s*unrestricted|tools:\s*(?:.*\n)+?(?:\s*-\s*(?:shell_exec|file_write|exec|system|code_exec|eval|python_exec)))", re.IGNORECASE | re.MULTILINE),
        description="Permissive tool access",
        impact="Could allow access to dangerous tools",
        remediation="Restrict tool access and implement proper validation"
    ),
    "verbose_logging": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"(?:log_level:\s*(?:debug|trace)|verbose:\s*true|debug:\s*true|logging:\s*(?:.*\n)+?(?:\s*level:\s*DEBUG))", re.IGNORECASE | re.MULTILINE),
        description="Verbose logging enabled",
        impact="Could leak sensitive information in logs",
        remediation="Use appropriate log levels in production"
    ),
    "frequent_api": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"(?:rate_limit:\s*(?:none|false|0)|max_requests:\s*(?:unlimited|-1)|repeat:\s*true|frequency:\s*unlimited|call:\s*['\"]https?://[^'\"]+['\"].*\n.*repeat:\s*true)", re.IGNORECASE | re.MULTILINE | re.DOTALL),
        description="No API rate limiting",
        impact="Could lead to API abuse or DOS",
        remediation="Implement proper rate limiting"
    ),
    "insecure_endpoint": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"(?:url|endpoint|api_url):\s*['\"]?http://[^'\"]+['\"]?|authentication:\s*(?:none|false|disabled|off)", re.IGNORECASE | re.MULTILINE),
        description="Insecure HTTP endpoint or missing authentication",
        impact="Could expose data in transit or allow unauthorized access",
        remediation="Use HTTPS for all API endpoints and enable proper authentication"
    ),
    "unsafe_yaml_deserialization": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"!!python/|!!python/object|!!python/object/apply:|!!python/object/new:|!!python/name:|yaml\.load\((?!.*Loader=yaml\.SafeLoader)", re.IGNORECASE),
        description="Unsafe YAML deserialization",
        impact="Could allow arbitrary code execution through YAML deserialization",
        remediation="Use yaml.safe_load() or explicitly specify SafeLoader"
    ),
    "persistent_memory_yaml": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"type:\s*\"?persistent\"?|store_history:\s*true", re.IGNORECASE),
        description="Persistent memory or history storage enabled (YAML)",
        impact="Sensitive data may be stored insecurely; agent state can be tampered with if storage is compromised.",
        remediation="Use ephemeral memory for sensitive operations. If persistence is required, ensure storage is encrypted and access-controlled. Regularly review and purge stored data."
    ),
    "allow_untrusted_input_yaml": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"allow_untrusted_input:\s*true", re.IGNORECASE),
        description="Agent configured to allow untrusted input (YAML)",
        impact="Increases risk of injection attacks (prompt injection, data injection) if input is not rigorously sanitized.",
        remediation="Treat all input as untrusted. Implement strong input validation and sanitization routines. Prefer structured input over free-form text where possible."
    ),
    "authentication_disabled_yaml": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"authentication_required:\s*false", re.IGNORECASE),
        description="Agent authentication requirement is disabled (YAML)",
        impact="Agent may be accessed or controlled by unauthorized users/systems, leading to misuse or data exposure.",
        remediation="Enable authentication for the agent. Use strong credentials and standard authentication protocols."
    ),
    "sensitive_logging_not_redacted_yaml": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"redact_sensitive:\s*false", re.IGNORECASE),
        description="Sensitive data may not be redacted from logs (YAML)",
        impact="Sensitive information (credentials, PII, confidential data) could be exposed in logs, increasing risk if logs are compromised.",
        remediation="Ensure sensitive data is redacted from logs by default. If verbose logging is needed for debugging, ensure logs are stored securely and access is strictly controlled."
    ),
}

# Action risk descriptions
ACTION_RISK_DESCRIPTIONS = {
    "execute_shell_command": "Allows execution of arbitrary shell commands which could be dangerous",
    "read_local_files": "Allows reading files from the local filesystem which could leak sensitive data",
    "write_local_files": "Allows writing to local filesystem which could be dangerous",
    "unrestricted_api_call": "Allows making unrestricted API calls which could be dangerous",
    "modify_system_settings": "Allows modification of system settings which could be dangerous",
    "network_access": "Allows unrestricted network access which could be dangerous"
}
