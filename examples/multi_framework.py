"""
Example configuration combining multiple agent frameworks and custom tools.
"""

from langchain.agents import Tool, AgentExecutor, LLMSingleActionAgent
from langchain.tools import ShellTool, RequestsGetTool
from autogen import AssistantAgent, UserProxyAgent
from typing import List, Dict
import os

# Custom high-risk tool
class SystemAccessTool:
    """Custom tool with system access capabilities."""
    def __init__(self):
        self.shell = ShellTool()
        self.allowed_commands = ["ls", "pwd", "echo"]
    
    def run(self, command: str) -> str:
        """Execute system commands."""
        return self.shell.run(command)

# Custom medium-risk tool
class DatabaseTool:
    """Tool for database operations."""
    def __init__(self, connection_string: str):
        self.connection = connection_string
    
    def query(self, sql: str) -> List[Dict]:
        """Execute SQL queries."""
        # Implementation here
        return []

# LangChain tools setup
langchain_tools = [
    ShellTool(),  # High risk
    RequestsGetTool(),  # Medium risk
    Tool(
        name="Calculator",
        func=lambda x: str(eval(x)),  # Low risk
        description="Perform calculations"
    )
]

# AutoGen agents setup
code_executor = UserProxyAgent(
    name="code_executor",
    human_input_mode="NEVER",
    code_execution_config={
        "work_dir": "workspace",
        "use_docker": False
    }
)

# Custom tools setup
system_tool = SystemAccessTool()  # High risk
db_tool = DatabaseTool("sqlite:///data.db")  # Medium risk

# Combined configuration
agent_config = {
    "tools": {
        "langchain": langchain_tools,
        "custom": [system_tool, db_tool]
    },
    "agents": {
        "executor": code_executor,
        "assistant": AssistantAgent(
            name="assistant",
            llm_config={"temperature": 0.7}
        )
    },
    "security": {
        "allow_system_access": True,  # High risk flag
        "allow_file_access": True,  # High risk flag
        "allow_network_access": True,  # Medium risk flag
    }
} 