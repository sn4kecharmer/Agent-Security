"""
Agent-specific security patterns for the security scanner.
These patterns focus on LLM agent-specific vulnerabilities and risks.
"""

from ..models import RiskLevel, SecurityInfo
import re

# LLM Configuration Patterns
LLM_CONFIG_PATTERNS = {
    "high_temperature": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"temperature:\s*([0-9]*\.?[0-9]+)"),
        description="High temperature setting in LLM configuration",
        impact="Increased unpredictability in outputs, potential for unsafe responses",
        remediation="Lower temperature or implement strict output validation"
    ),
    "unlimited_tokens": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"max_tokens:\s*null|max_tokens:\s*[0-9]{5,}"),
        description="Unrestricted token length in LLM configuration",
        impact="Resource exhaustion, token stuffing attacks",
        remediation="Set appropriate token limits based on use case"
    ),
    "system_prompt_injection": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"system_message:\s*\{.*?\}|\$\{.*?\}"),
        description="System prompt template injection vulnerability",
        impact="Prompt injection leading to unauthorized behavior or system prompt leakage",
        remediation="Sanitize system prompts, use strict validation, avoid template literals in system prompts"
    )
}

# Agent Chain Security Patterns
AGENT_CHAIN_PATTERNS = {
    "unrestricted_chaining": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_chain:\s*true|chain_length:\s*null"),
        description="Unrestricted tool chaining capability",
        impact="Complex attack chains, resource exhaustion, unauthorized tool combinations",
        remediation="Limit chain length, implement chain validation, restrict tool combinations"
    ),
    "missing_tool_validation": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"validate_tools:\s*false|skip_validation:\s*true"),
        description="Tool validation disabled",
        impact="Unauthorized tool access or misuse",
        remediation="Enable tool validation, implement tool allow-listing, validate tool inputs"
    ),
    "tool_registration": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_tool_registration:\s*true|dynamic_tools:\s*true"),
        description="Dynamic tool registration enabled",
        impact="Unauthorized tool injection, privilege escalation",
        remediation="Disable dynamic tool registration, use static tool configurations"
    )
}

# Memory and Context Patterns
MEMORY_PATTERNS = {
    "persistent_memory": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"memory_type:\s*'persistent'|store_history:\s*true"),
        description="Persistent memory storage enabled",
        impact="Information leakage, unauthorized data retention",
        remediation="Use ephemeral memory, implement memory sanitization, limit retention"
    ),
    "unlimited_context": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"context_window:\s*null|max_context:\s*unlimited"),
        description="Unrestricted context window",
        impact="Resource exhaustion, context manipulation",
        remediation="Set appropriate context limits, implement context validation"
    ),
    "memory_injection": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_memory_manipulation:\s*true|memory_editing:\s*true"),
        description="Memory manipulation capabilities enabled",
        impact="Memory injection attacks, unauthorized state manipulation",
        remediation="Disable memory manipulation, implement memory access controls"
    )
}

# Output Validation Patterns
OUTPUT_PATTERNS = {
    "missing_validation": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"validate_outputs:\s*false|skip_output_check:\s*true"),
        description="Output validation disabled",
        impact="Malicious or unsafe outputs, output injection",
        remediation="Implement output validation and sanitization, use output schemas"
    ),
    "unsafe_parsing": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"parse_mode:\s*'unsafe'|allow_raw_output:\s*true"),
        description="Unsafe output parsing configuration",
        impact="Code injection, command injection through outputs",
        remediation="Use safe parsing modes, implement output sanitization"
    ),
    "output_filtering": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"output_filtering:\s*false|skip_filtering:\s*true"),
        description="Output filtering disabled",
        impact="Sensitive data leakage, unsafe content",
        remediation="Enable output filtering, implement content policies"
    )
}

# Resource Management Patterns
RESOURCE_PATTERNS = {
    "missing_rate_limits": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"rate_limit:\s*null|rate_limit:\s*0"),
        description="Missing rate limits",
        impact="DoS attacks, resource exhaustion",
        remediation="Implement rate limiting for all operations"
    ),
    "unlimited_parallel": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"max_parallel:\s*null|max_concurrent:\s*unlimited"),
        description="Unlimited parallel execution",
        impact="Resource exhaustion, race conditions",
        remediation="Set appropriate concurrency limits"
    ),
    "resource_quotas": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"resource_quotas:\s*null|unlimited_resources:\s*true"),
        description="Missing resource quotas",
        impact="Resource exhaustion, DoS",
        remediation="Implement resource quotas and monitoring"
    )
}

# Agent Escape Prevention Patterns
ESCAPE_PREVENTION_PATTERNS = {
    "self_modification": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_self_modification:\s*true|self_improvement:\s*true"),
        description="Self-modification capabilities enabled",
        impact="Unauthorized behavior changes, security bypass",
        remediation="Disable self-modification, implement strict permission boundaries"
    ),
    "model_switching": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_model_switching:\s*true|dynamic_model:\s*true"),
        description="Dynamic model switching enabled",
        impact="Unauthorized model access, capability escalation",
        remediation="Use fixed model configurations, implement model access controls"
    ),
    "config_modification": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"allow_config_changes:\s*true|dynamic_config:\s*true"),
        description="Runtime configuration modification enabled",
        impact="Security control bypass, unauthorized configuration changes",
        remediation="Use immutable configurations, implement configuration validation"
    )
}

# Combine all patterns
AGENT_SECURITY_PATTERNS = {
    **LLM_CONFIG_PATTERNS,
    **AGENT_CHAIN_PATTERNS,
    **MEMORY_PATTERNS,
    **OUTPUT_PATTERNS,
    **RESOURCE_PATTERNS,
    **ESCAPE_PREVENTION_PATTERNS
} 