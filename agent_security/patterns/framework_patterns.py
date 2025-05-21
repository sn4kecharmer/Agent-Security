"""
Framework-specific security patterns for various agent frameworks.
"""

from ..models import SecurityInfo, RiskLevel
import re

FRAMEWORK_PATTERNS = {
    # AutoGen Patterns
    "autogen_unrestricted": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"allow_code_execution:\s*true|allow_shell_commands:\s*true|allow_system_commands:\s*true"),
        description="Unrestricted AutoGen capabilities",
        impact="Agent has unrestricted access to system resources",
        remediation="Limit AutoGen capabilities and implement proper sandboxing"
    ),
    
    # LangChain Patterns
    "langchain_unsafe_agent": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"AgentType.ZERO_SHOT_REACT_DESCRIPTION|agent=AgentExecutor\(.*allow_delegation=True"),
        description="Unsafe LangChain agent configuration",
        impact="Agent may execute arbitrary actions without proper validation",
        remediation="Use restricted agent types and implement proper validation"
    ),
    
    # CrewAI Patterns
    "crewai_unsafe_config": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"process_chain=True|allow_delegation=True|verbose=True.*validate=False"),
        description="Unsafe CrewAI configuration",
        impact="Potential unauthorized task execution and insufficient validation",
        remediation="Disable process chaining and implement proper validation"
    ),
    
    # Custom Framework Patterns
    "custom_framework_risks": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"custom_agent\.execute|custom_llm\.run|custom_tool\.invoke"),
        description="Custom framework usage detected",
        impact="Potential security risks from unvalidated custom implementations",
        remediation="Ensure custom implementations follow security best practices"
    ),
    
    # Framework Interaction Risks
    "framework_interaction": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"chain_of_agents|multi_agent_system|agent_collaboration"),
        description="Multi-framework interaction detected",
        impact="Potential security risks from framework interactions",
        remediation="Implement proper isolation and validation between frameworks"
    ),
} 