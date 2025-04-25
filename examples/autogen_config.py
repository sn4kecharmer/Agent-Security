"""
Example AutoGen agent configuration with various tools and capabilities.
"""

from autogen import AssistantAgent, UserProxyAgent, config_list_from_json
from autogen.agentchat.contrib.retrieve_assistant_agent import RetrieveAssistantAgent
from autogen.code_utils import extract_code
import os

# Configuration with potential security implications
config_list = [{
    "model": "gpt-4",
    "api_key": os.getenv("OPENAI_API_KEY"),
}]

# High-risk agent with shell access
code_executor = UserProxyAgent(
    name="executor",
    human_input_mode="NEVER",
    system_message="Execute code and return results",
    code_execution_config={
        "work_dir": "workspace",
        "use_docker": False,  # Direct system access
    }
)

# Medium-risk agent with web access
researcher = AssistantAgent(
    name="researcher",
    system_message="Research and analyze information",
    llm_config={
        "config_list": config_list,
        "tools": ["web_search", "url_fetch"]
    }
)

# Low-risk agent with limited capabilities
calculator = AssistantAgent(
    name="calculator",
    system_message="Perform calculations",
    llm_config={
        "config_list": config_list,
        "tools": ["calculator"]
    }
)

# Agent with file access
file_manager = RetrieveAssistantAgent(
    name="file_manager",
    system_message="Manage and process files",
    llm_config={
        "config_list": config_list,
        "tools": ["read_file", "write_file"]
    }
) 