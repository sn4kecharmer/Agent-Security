"""
Environment security patterns for detecting environment-related vulnerabilities.
"""

from ..models import SecurityInfo, RiskLevel
import re

ENVIRONMENT_PATTERNS = {
    # API Key Exposure
    "exposed_api_key": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"(api[_-]?key|token|secret|password|credential)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?"),
        description="Exposed API key or credential",
        impact="Potential unauthorized access and credential compromise",
        remediation="Use environment variables or secure credential storage"
    ),
    
    # Environment Variable Injection
    "env_injection": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"\$\{.*\}|\$\(.*\)|%\{.*\}|%.*%"),
        description="Environment variable injection vulnerability",
        impact="Potential command injection or information disclosure",
        remediation="Validate and sanitize environment variable usage"
    ),
    
    # Sandbox Escape
    "sandbox_escape": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"disable[_-]?sandbox|no[_-]?sandbox|sandbox:\s*false|container\.escape|break[_-]?out"),
        description="Potential sandbox escape vulnerability",
        impact="Agent may escape containment and access host system",
        remediation="Enforce proper sandboxing and containment"
    ),
    
    # Resource Exhaustion
    "resource_exhaustion": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"max[_-]?(memory|cpu|threads|processes):\s*(unlimited|null|none|\d{7,})|resource[_-]?limit:\s*false"),
        description="Missing resource limits",
        impact="Potential denial of service through resource exhaustion",
        remediation="Set appropriate resource limits and monitoring"
    ),
    
    # Insecure Temp Files
    "insecure_tempfile": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"tempfile\.(mk(temp|stemp)|NamedTemporaryFile)|/tmp/.*\+w"),
        description="Insecure temporary file usage",
        impact="Potential information disclosure or race conditions",
        remediation="Use secure temporary file creation with proper permissions"
    ),
    
    # Insecure Logging
    "insecure_logging": SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"log[_-]level:\s*(debug|trace)|debug[_-]mode:\s*true|verbose[_-]logging:\s*true"),
        description="Excessive logging or debug information",
        impact="Potential information disclosure through logs",
        remediation="Configure appropriate logging levels for production"
    ),
} 