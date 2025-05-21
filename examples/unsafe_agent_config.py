"""
Example of unsafe agent configurations that would trigger security warnings.
"""

from langchain import Tool
from crewai import Agent, Task, Crew
from crewai.memory import Memory

# Unsafe LLM configuration
llm_config = {
    "temperature": 0.9,  # High temperature
    "max_tokens": None,  # Unlimited tokens
    "system_message": "${USER_PROMPT}",  # Template injection vulnerability
}

# Unsafe agent configuration
agent_config = {
    "allow_chain": True,  # Unrestricted tool chaining
    "validate_tools": False,  # Tool validation disabled
    "allow_tool_registration": True,  # Dynamic tool registration
    "memory_type": "persistent",  # Persistent memory
    "context_window": None,  # Unlimited context
    "allow_memory_manipulation": True,  # Memory manipulation enabled
    "validate_outputs": False,  # Output validation disabled
    "parse_mode": "unsafe",  # Unsafe parsing
    "output_filtering": False,  # Output filtering disabled
    "rate_limit": None,  # No rate limiting
    "max_parallel": None,  # Unlimited parallel execution
    "resource_quotas": None,  # No resource quotas
    "allow_self_modification": True,  # Self-modification enabled
    "allow_model_switching": True,  # Model switching enabled
    "allow_config_changes": True,  # Config modification enabled
}

# Unsafe tool definitions
dangerous_tools = [
    Tool(
        name="shell_executor",
        description="Execute any shell command",
        func=lambda x: eval(x)  # Unsafe code execution
    ),
    Tool(
        name="file_access",
        description="Unrestricted access to file system",
        func=lambda x: open(x).read()  # Unrestricted file access
    )
]

# Unsafe memory configuration
memory = Memory(
    store_history=True,  # Persistent history
    memory_editing=True  # Memory manipulation
)

# Unsafe agent creation
agent = Agent(
    name="unsafe_agent",
    llm_config=llm_config,
    tools=dangerous_tools,
    memory=memory,
    allow_delegation=True
)

# Unsafe task configuration
task = Task(
    description="Task with unrestricted capabilities",
    agent=agent,
    expected_output="Any output will be accepted without validation"
)

# Unsafe crew configuration
crew = Crew(
    agents=[agent],
    tasks=[task],
    process_chain=True,
    verbose=True
)

# Run with all unsafe settings
crew.kickoff() 