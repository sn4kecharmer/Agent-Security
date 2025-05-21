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
    "crewai_memory": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"from\s+crewai\.memory\s+import|import\s+crewai\.memory"),
        description="CrewAI memory usage detected",
        impact="Potential data persistence and memory manipulation risks",
        remediation="Use ephemeral memory and implement proper memory sanitization"
    ),
    "crewai_agent": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"Agent\("),
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
        risk_level=RiskLevel.CRITICAL,
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
    )
}

# YAML tool patterns
YAML_TOOL_PATTERNS = {
    "risky_tool_description": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"description:\s*[\"']?(?:arbitrary|any|unrestricted|full access)[\"']?", re.IGNORECASE),
        description="Risky tool description detected",
        impact="Potential security risks from unrestricted tool capabilities",
        remediation="Use specific, limited tool descriptions and implement proper validation"
    ),
    "unsafe_tool_config": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_all:\s*true|validate:\s*false|validation:\s*false"),
        description="Unsafe tool configuration detected",
        impact="Potential security risks from disabled validation",
        remediation="Enable validation and implement proper security controls"
    ),
    "unsafe_execution": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"mode:\s*unrestricted|validation:\s*false|monitoring:\s*false"),
        description="Unsafe execution configuration detected",
        impact="Potential security risks from unrestricted execution",
        remediation="Enable validation and monitoring, implement proper security controls"
    ),
    "shell_tool": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"tools:\s*\n\s+shell:\s*\n\s+enabled:\s*true", re.MULTILINE),
        description="Shell command execution tool enabled",
        impact="Allows execution of arbitrary shell commands, which could lead to system compromise",
        remediation="Disable shell command execution or strictly limit allowed commands using an allowlist"
    ),
    "python_repl_tool": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"tools:\s*\n\s+python_repl:\s*\n\s+enabled:\s*true", re.MULTILINE),
        description="Python REPL tool enabled",
        impact="Allows execution of arbitrary Python code, which could lead to system compromise",
        remediation="Disable Python REPL or use a sandboxed environment with restricted capabilities"
    ),
    "unrestricted_web_access": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"tools:\s*\n\s+web:\s*\n\s+enabled:\s*true", re.MULTILINE),
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
    )
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