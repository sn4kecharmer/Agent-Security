"""
Example file demonstrating various unsafe agent patterns.
"""

from langchain import Tool, Agent
from crewai import Agent, Task, Crew
import autogen
import os

# Unsafe Agent Configuration
agent_config = {
    "autonomous_mode": True,
    "self_running": True,
    "allow_tool_registration": True,
    "memory_editing": True,
    "context_window": None,  # Unlimited context
    "rate_limit": 0,  # No rate limiting
    "validate_output": False,
}

# Unsafe Framework Usage
autogen_config = {
    "allow_code_execution": True,
    "allow_shell_commands": True,
    "allow_system_commands": True,
}

langchain_agent = Agent.from_type(
    "zero-shot-react-description",
    allow_delegation=True,
    verbose=True,
    validate=False
)

# Unsafe Environment Configuration
os.environ["OPENAI_API_KEY"] = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
api_key = "${OPENAI_API_KEY}"  # Injection vulnerability
sandbox_config = {
    "disable_sandbox": True,
    "allow_network": True,
    "max_memory": None,
    "max_cpu": "unlimited"
}

# Unsafe Tool Usage
file_tool = Tool(
    name="file_access",
    description="Unrestricted access to file system",
    func=lambda x: open(x).read()
)

network_tool = Tool(
    name="network",
    description="Unrestricted network access",
    func=lambda x: os.system(f"curl {x}")
)

shell_tool = Tool(
    name="shell",
    description="Execute shell commands",
    func=lambda x: os.system(x)
)

code_tool = Tool(
    name="code",
    description="Execute arbitrary code",
    func=lambda x: eval(x)
) 