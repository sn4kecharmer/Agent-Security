"""
Agent-specific security patterns for detecting common agent security risks.
"""

from ..models import SecurityInfo, RiskLevel
import re

AGENT_PATTERNS = {
    # Autonomous Mode Detection
    "autonomous_mode": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"autonomous|self_running|unsupervised|auto_execute", re.IGNORECASE),
        description="Autonomous mode detected",
        impact="Agent may operate without proper oversight or control",
        remediation="Implement supervision mechanisms and control boundaries"
    ),
    
    # Tool Registration
    "unsafe_tool_registration": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_tool_registration:\s*true|dynamic_tools:\s*true|register_tools:\s*true"),
        description="Unsafe dynamic tool registration",
        impact="Potential execution of unauthorized tools",
        remediation="Use static tool registration and validate tool sources"
    ),
    
    # Memory Manipulation
    "memory_manipulation": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"memory_editing:\s*true|allow_memory_manipulation:\s*true|edit_history:\s*true"),
        description="Memory manipulation enabled",
        impact="Agent can modify its memory/history which may lead to unexpected behavior",
        remediation="Disable memory manipulation or implement strict validation"
    ),
    
    # Context Window
    "unlimited_context": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"context_window:\s*(unlimited|null|none|\d{7,})", re.IGNORECASE),
        description="Unlimited or very large context window",
        impact="Potential resource exhaustion and token limit issues",
        remediation="Set reasonable context window limits based on model capabilities"
    ),
    
    # Rate Limiting
    "missing_rate_limit": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"rate_limit:\s*(0|null|none|unlimited)", re.IGNORECASE),
        description="Missing or disabled rate limiting",
        impact="Potential API abuse or resource exhaustion",
        remediation="Implement appropriate rate limiting"
    ),
    
    # Output Validation
    "disabled_output_validation": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"validate_output:\s*false|output_filtering:\s*false|skip_validation:\s*true"),
        description="Output validation disabled",
        impact="Agent outputs may contain malicious content or unintended commands",
        remediation="Enable output validation and implement content filtering"
    ),
} 