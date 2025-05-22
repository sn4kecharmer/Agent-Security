"""
Sample safe agent code with security best practices.
"""

import os
from pathlib import Path
import requests
from langchain.agents import Tool, initialize_agent
from langchain.chat_models import ChatOpenAI

# Allowlist for domains
ALLOWED_DOMAINS = ["api.example.com", "data.example.org"]

# Allowlist for file paths
ALLOWED_PATHS = ["/var/log/agent", "./data"]

# Restricted commands
RESTRICTED_COMMANDS = ["rm", "sudo", "chmod"]

def create_safe_agent():
    # Create LLM with safe temperature
    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0.2,
        openai_api_key=os.environ.get("OPENAI_API_KEY"),
        max_tokens=500
    )
    
    # Safe file read tool with path validation
    def read_file(file_path):
        """Read file from allowed paths only."""
        path = Path(file_path)
        
        # Validate path is allowed
        is_allowed = any(
            str(path).startswith(allowed_path) 
            for allowed_path in ALLOWED_PATHS
        )
        
        if not is_allowed:
            return f"Error: Access to {file_path} is not allowed"
        
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"
    
    # Safe HTTP request tool with domain validation
    def make_safe_request(url):
        """Make HTTP request to allowed domains only."""
        from urllib.parse import urlparse
        
        # Extract domain from URL
        domain = urlparse(url).netloc
        
        # Check if domain is allowed
        if domain not in ALLOWED_DOMAINS:
            return f"Error: Access to domain {domain} is not allowed"
        
        try:
            response = requests.get(url, timeout=5)
            return response.text
        except Exception as e:
            return f"Error making request: {str(e)}"
    
    # Define tools
    tools = [
        Tool(
            name="read_file",
            func=read_file,
            description="Read content from an allowed file path"
        ),
        Tool(
            name="make_request",
            func=make_safe_request,
            description="Make HTTP request to an allowed domain"
        )
    ]
    
    # Initialize agent with human approval
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent="zero-shot-react-description",
        verbose=True,
        handle_parsing_errors=True
    )
    
    return agent

def main():
    agent = create_safe_agent()
    
    # Human in the loop
    user_input = input("Enter your query: ")
    print("About to execute agent with this input. Proceed? (y/n)")
    confirmation = input()
    
    if confirmation.lower() == 'y':
        try:
            response = agent.run(user_input)
            print(response)
            
            # Safe logging
            log_dir = Path("./logs")
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / "agent_activity.log"
            
            with open(log_file, "a") as f:
                f.write(f"Query: {user_input}\nResponse: {response}\n\n")
                
        except Exception as e:
            print(f"Error running agent: {str(e)}")
    else:
        print("Operation cancelled by user")

if __name__ == "__main__":
    main() 