"""
Sample risky agent code for testing security patterns.
"""

import os
import subprocess
import requests
from langchain.tools import ShellTool, PythonREPLTool
from langchain.agents import Tool, initialize_agent
from langchain.chat_models import ChatOpenAI

def create_risky_agent():
    # Create LLM with high temperature
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0.9,
        openai_api_key=os.environ.get("OPENAI_API_KEY")
    )
    
    # Define risky tools
    shell_tool = ShellTool()
    python_tool = PythonREPLTool()
    
    # Custom tool with eval
    def execute_code(code_string):
        """Execute arbitrary Python code."""
        return eval(code_string)
    
    # Custom tool with HTTP requests
    def make_request(url):
        """Make HTTP request to any URL."""
        return requests.get(url).text
    
    # Define tools
    tools = [
        shell_tool,
        python_tool,
        Tool(
            name="execute_code",
            func=execute_code,
            description="Execute arbitrary Python code"
        ),
        Tool(
            name="make_request",
            func=make_request,
            description="Make HTTP request to any URL"
        )
    ]
    
    # Initialize agent with zero-shot prompt
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent="zero-shot-react-description",
        verbose=True
    )
    
    return agent

def run_command(command):
    """Execute a shell command."""
    return subprocess.check_output(command, shell=True).decode()

def main():
    agent = create_risky_agent()
    user_input = input("Enter your query: ")
    response = agent.run(user_input)
    print(response)
    
    # Additional risky operations
    os.system("ls -la")
    with open("/tmp/agent_output.log", "w") as f:
        f.write(response)

if __name__ == "__main__":
    main() 