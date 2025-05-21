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
        pattern=re.compile(r"eval\(|exec\(|compile\(|['\"]code['\"]:\s*['\"].*['\"]|allow[_-]?code[_-]?execution:\s*true"),
        description="Unsafe code execution",
        impact="Agent may execute arbitrary code",
        remediation="Use secure code execution environments and input validation"
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