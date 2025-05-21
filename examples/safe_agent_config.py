"""
Example of safe agent configurations with proper security controls.
"""

from langchain import Tool
from crewai import Agent, Task, Crew
from crewai.memory import Memory
import os

# Safe LLM configuration
llm_config = {
    "temperature": 0.2,  # Low temperature for predictability
    "max_tokens": 1000,  # Limited token count
    "system_message": "You are a helpful assistant with strict security boundaries.",  # Static system message
}

# Safe agent configuration
agent_config = {
    "allow_chain": False,  # No unrestricted chaining
    "validate_tools": True,  # Tool validation enabled
    "allow_tool_registration": False,  # Static tool configuration
    "memory_type": "ephemeral",  # Non-persistent memory
    "context_window": 4096,  # Limited context window
    "allow_memory_manipulation": False,  # No memory manipulation
    "validate_outputs": True,  # Output validation enabled
    "parse_mode": "safe",  # Safe parsing
    "output_filtering": True,  # Output filtering enabled
    "rate_limit": 10,  # Rate limiting enabled
    "max_parallel": 5,  # Limited parallel execution
    "resource_quotas": {
        "max_memory": "1GB",
        "max_cpu": 50
    },
    "allow_self_modification": False,  # No self-modification
    "allow_model_switching": False,  # Fixed model configuration
    "allow_config_changes": False,  # Immutable configuration
}

# Safe tool definitions with proper validation
def safe_file_read(path: str) -> str:
    """Safely read a file with proper validation."""
    # Validate path is within allowed directory
    allowed_dir = os.path.abspath("./data")
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(allowed_dir):
        raise ValueError("Access denied: Path outside allowed directory")
    
    # Check file extension
    allowed_extensions = {".txt", ".md", ".json"}
    if not any(abs_path.endswith(ext) for ext in allowed_extensions):
        raise ValueError("Access denied: Invalid file type")
    
    # Read file safely
    try:
        with open(abs_path, "r") as f:
            return f.read()
    except Exception as e:
        raise ValueError(f"Error reading file: {str(e)}")

safe_tools = [
    Tool(
        name="safe_file_reader",
        description="Read files from the allowed directory with proper validation",
        func=safe_file_read
    )
]

# Safe memory configuration
memory = Memory(
    store_history=False,  # No persistent history
    memory_editing=False  # No memory manipulation
)

# Safe agent creation
agent = Agent(
    name="safe_agent",
    llm_config=llm_config,
    tools=safe_tools,
    memory=memory,
    allow_delegation=False
)

# Safe task configuration
task = Task(
    description="Task with proper security controls",
    agent=agent,
    expected_output="Output will be validated and sanitized"
)

# Safe crew configuration
crew = Crew(
    agents=[agent],
    tasks=[task],
    process_chain=False,
    verbose=True
)

# Run with all security controls enabled
crew.kickoff() 