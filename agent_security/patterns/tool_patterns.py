"""
Tool security patterns for detecting tool-related vulnerabilities.
"""

from ..models import SecurityInfo, RiskLevel
import re

TOOL_PATTERNS = {
    # File System Access
    "unrestricted_file_access": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"(open|read|write)_file.*allow_all:\s*true|path:\s*['\"]?/|access:\s*['\"]?full['\"]?"),
        description="Unrestricted file system access",
        impact="Agent may access or modify sensitive files",
        remediation="Implement proper file access controls and path validation"
    ),
    
    # Network Access
    "unrestricted_network": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"allow[_-]?network:\s*true|network[_-]?access:\s*unrestricted|allowed[_-]?domains:\s*\[\s*['\"]?\*['\"]?\s*\]"),
        description="Unrestricted network access",
        impact="Agent may make unauthorized network connections",
        remediation="Implement network access controls and domain whitelisting"
    ),
    
    # Shell Command Execution
    "shell_execution": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"shell[_-]?access:\s*true|execute[_-]?command|os\.system|subprocess\.(call|run|Popen)|exec\("),
        description="Shell command execution capability",
        impact="Agent may execute arbitrary system commands",
        remediation="Disable shell access or implement strict command validation"
    ),
    
    # Code Execution
    "unsafe_code_execution": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        # Pattern to detect eval(), exec(), compile() calls or code: blocks with potentially unsafe code.
        # It also checks for tool configurations that explicitly allow code execution.
        # Improved to better attribute code execution within specific tool blocks in YAML.
        pattern=re.compile(r"code:\s*.*?eval\(|code:\s*.*?exec\(|code:\s*.*?compile\(|eval\(|exec\(|compile\(|allow[_-]?code[_-]?execution:\s*true"),
        description="Unsafe code execution",
        impact="Agent may execute arbitrary code",
        remediation="Use secure code execution environments and input validation"
    ),

    "enabled_shell_tool": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"type:\s*['\"]?ShellTool['\"]?.*?enabled:\s*true", re.DOTALL),
        description="Enabled ShellTool",
        impact="Agent may execute arbitrary shell commands via the ShellTool",
        remediation="Disable ShellTool if not essential, or implement strict validation and sandboxing for its inputs."
    ),

    "unsafe_browser_tool": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"type:\s*['\"]?BrowserTool['\"]?.*?allow_all_hosts:\s*true", re.DOTALL),
        description="BrowserTool with allow_all_hosts: true",
        impact="Agent may access any website, potentially including malicious sites or internal resources.",
        remediation="Restrict BrowserTool to a whitelist of allowed hosts/domains."
    ),

    "untrusted_input": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"allow_untrusted_input:\s*true"),
        description="Allowing untrusted input",
        impact="Agent may process malicious or malformed input, leading to vulnerabilities.",
        remediation="Set allow_untrusted_input to false and validate/sanitize all inputs."
    ),

    "missing_authentication": SecurityInfo(
        risk_level=RiskLevel.MEDIUM, # Adjusted from HIGH as impact varies
        pattern=re.compile(r"authentication_required:\s*false"),
        description="Authentication not required",
        impact="Tools or agent functionalities may be accessed without proper authentication, potentially allowing unauthorized use.",
        remediation="Enable authentication for sensitive tools and agent functionalities."
    ),

    "sensitive_data_logging": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"logging:\s*.*?redact_sensitive:\s*false", re.DOTALL),
        description="Sensitive data may not be redacted from logs",
        impact="Sensitive information might be logged, increasing risk of exposure.",
        remediation="Ensure redact_sensitive is true in logging configurations or implement custom log filtering."
    ),
    
    # Tool Chain Risks
    "unsafe_tool_chain": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"chain[_-]?tools:\s*true|allow[_-]?composition:\s*true|tool[_-]?pipeline"),
        description="Unsafe tool chaining",
        impact="Tools may be combined in unsafe ways",
        remediation="Implement proper tool chain validation and restrictions"
    ),
    
    # Tool Validation
    "missing_tool_validation": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"validate[_-]?tools:\s*false|skip[_-]?validation:\s*true|tool[_-]?check:\s*false"),
        description="Missing tool validation",
        impact="Tools may be used without proper validation",
        remediation="Enable and implement proper tool validation"
    ),
} 