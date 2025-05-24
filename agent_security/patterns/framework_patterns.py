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
    "autogen_host_code_execution": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r'(UserProxyAgent|AssistantAgent)\s*\([^)]*code_execution_config\s*=\s*(?:\{[^}]*"use_docker":\s*False|\(.*use_docker=False\))', re.IGNORECASE),
        description="AutoGen agent configured for direct host code execution (use_docker: False).",
        impact="Code executed by the agent runs directly on the host, potentially leading to system compromise.",
        remediation="Set `use_docker=True` in `code_execution_config` to run code in a container, or ensure the agent only executes thoroughly vetted code."
    ),
    
    # LangChain Patterns
    "langchain_unsafe_agent": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        # Adjusted to be more specific and avoid conflict with CrewAI. Catches common unsafe agent initializations.
        pattern=re.compile(r"AgentType\.(ZERO_SHOT_REACT_DESCRIPTION|CONVERSATIONAL_REACT_DESCRIPTION)|ConversationalRetrievalChain|RetrievalQA\.from_chain_type|load_qa_chain|initialize_agent\(.*(ChatAgent|ZeroShotAgent|StructuredChatAgent)"),
        description="Potentially unsafe LangChain agent configuration or chain initialization",
        impact="Agent may execute arbitrary actions or access data without proper validation if not carefully configured.",
        remediation="Use restricted agent types, ensure proper validation, and apply least privilege principle to data access."
    ),

    "langchain_llm_single_action_agent": SecurityInfo( # Specific pattern for LLMSingleActionAgent
        risk_level=RiskLevel.MEDIUM, # Default risk, actual risk depends on tools
        pattern=re.compile(r"LLMSingleActionAgent"),
        description="LangChain LLMSingleActionAgent detected",
        impact="The security impact depends on the tools allowed and the agent's configuration.",
        remediation="Review allowed tools for potential risks. Ensure proper input validation and output parsing."
    ),

    "langchain_shell_tool": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"ShellTool"),
        description="LangChain ShellTool usage detected",
        impact="Allows execution of arbitrary shell commands, which is highly risky.",
        remediation="Avoid ShellTool if possible. If essential, use extreme caution, validate inputs strictly, and consider sandboxing."
    ),

    "langchain_python_repl_tool": SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"PythonREPLTool"),
        description="LangChain PythonREPLTool usage detected",
        impact="Allows execution of arbitrary Python code, which is highly risky.",
        remediation="Avoid PythonREPLTool if possible. If essential, use extreme caution, validate inputs strictly, and consider sandboxing."
    ),

    "langchain_requests_get_tool": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"RequestsGetTool"), # Simple string match for the class name
        description="LangChain RequestsGetTool usage detected",
        impact="Agent can make GET requests to any URL, potentially accessing sensitive internal or external resources or SSRF.",
        remediation="Restrict tool usage to specific, trusted URLs or implement a strict allow-list for domains. Be cautious with dynamic inputs to this tool."
    ),

    "langchain_verbose_logging": SecurityInfo(
        risk_level=RiskLevel.LOW, # Verbosity itself is not a vulnerability, but can leak info
        pattern=re.compile(r"verbose\s*=\s*True"), # Looks for "verbose=True" or "verbose = True"
        description="LangChain verbose logging enabled (e.g., verbose=True)",
        impact="May log sensitive information, including prompts, tool inputs/outputs, or intermediate reasoning steps.",
        remediation="Disable verbose logging in production or ensure logs are securely stored and sensitive data is redacted."
    ),
    
    # CrewAI Patterns
    "crewai_unsafe_config": SecurityInfo(
        risk_level=RiskLevel.HIGH,
        # Made more specific to CrewAI initializations (e.g. Agent( or Task() )
        pattern=re.compile(r"Agent\s*\(.*(process_chain\s*=\s*True|allow_delegation\s*=\s*True|verbose\s*=\s*True)|Task\s*\(.*(validate\s*=\s*False)"),
        description="Unsafe CrewAI configuration (e.g. agent or task allowing delegation/verbose or disabling validation)",
        impact="Potential unauthorized task execution, data leakage through verbose logs, or insufficient validation.",
        remediation="Disable process chaining/delegation if not needed, disable verbose logging in production, and enable validation."
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