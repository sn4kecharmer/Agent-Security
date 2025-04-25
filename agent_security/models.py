"""
Shared data models for the security scanner.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional, Pattern, NamedTuple, List, Any
import re

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"  # 🔴
    HIGH = "HIGH"         # 🟠
    MEDIUM = "MEDIUM"     # 🟡
    LOW = "LOW"          # 🟢
    
    def __lt__(self, other):
        order = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1
        }
        return order[self] < order[other]
    
    def __gt__(self, other):
        order = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1
        }
        return order[self] > order[other]

@dataclass
class SecurityInfo:
    risk_level: RiskLevel
    description: str
    impact: str
    remediation: str
    pattern: re.Pattern
    severity: str = ""  # Emoji representation of risk level
    affected_lines: List[int] = None
    confidence: str = "High"  # High, Medium, Low
    category: str = ""  # e.g., "Input Validation", "Access Control", etc.
    cwe: List[str] = None  # Common Weakness Enumeration IDs
    owasp: List[str] = None  # OWASP Top 10 categories

    def __post_init__(self):
        # Set severity emoji based on risk level
        self.severity = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH: "🟠",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.LOW: "🟢"
        }.get(self.risk_level, "")
        
        # Initialize lists if None
        if self.affected_lines is None:
            self.affected_lines = []
        if self.cwe is None:
            self.cwe = []
        if self.owasp is None:
            self.owasp = []

@dataclass
class SecurityFinding:
    pattern: str
    risk_level: RiskLevel
    line_number: Optional[int] = None
    context: Optional[str] = None
    security_info: Optional[SecurityInfo] = None

@dataclass
class SecurityReport:
    findings: List[SecurityFinding]
    overall_risk: RiskLevel
    file_path: str
    timestamp: str
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [
                {
                    "pattern": f.pattern,
                    "risk_level": f.risk_level.value,
                    "line_number": f.line_number,
                    "context": f.context,
                    "security_info": {
                        "description": f.security_info.description,
                        "impact": f.security_info.impact,
                        "remediation": f.security_info.remediation,
                        "severity": f.security_info.severity,
                        "confidence": f.security_info.confidence,
                        "category": f.security_info.category,
                        "cwe": f.security_info.cwe,
                        "owasp": f.security_info.owasp
                    } if f.security_info else None
                }
                for f in self.findings
            ],
            "overall_risk": self.overall_risk.value,
            "file_path": self.file_path,
            "timestamp": self.timestamp,
            "metadata": self.metadata or {}
        }

class ToolUsage:
    """Represents a detected tool usage with security implications."""
    
    def __init__(self, name: str, security_info: SecurityInfo, line_number: Optional[int] = None, context: Optional[str] = None, match: Optional[str] = None):
        self.name = name
        self.security_info = security_info
        self.line_number = line_number
        self.context = context
        self.match = match
    
    @property
    def risk_level(self) -> RiskLevel:
        return self.security_info.risk_level

    def add_finding(self, finding: SecurityFinding):
        """Add a finding to the report."""
        self.findings.append(finding)
        if finding.risk_level > self.overall_risk:
            self.overall_risk = finding.risk_level

    def to_dict(self) -> dict:
        """Convert the report to a dictionary for JSON output."""
        return {
            "findings": [
                {
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "pattern": f.pattern,
                    "risk_level": f.risk_level.name,
                    "context": f.context
                }
                for f in self.findings
            ],
            "overall_risk": self.overall_risk.name
        } 