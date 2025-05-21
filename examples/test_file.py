from langchain import Tool
import os
import requests

# Test pattern 1: Shell command execution
def run_command(cmd):
    os.system(cmd)  # CRITICAL: Arbitrary command execution

# Test pattern 2: Unrestricted web request
def fetch_url(url):
    response = requests.get(url)  # HIGH: Unrestricted web request
    return response.text

# Test pattern 3: Memory usage
from crewai import Agent, Task, Crew
from crewai.memory import Memory

# Create an agent with memory
agent = Agent(
    name="test_agent",
    goal="Test agent",
    backstory="Test backstory",
    memory=Memory()  # MEDIUM: Memory usage
)

# Create a task
task = Task(
    description="Test task",
    agent=agent
)

# Create a crew
crew = Crew(
    agents=[agent],
    tasks=[task]
)

# Run the crew
crew.kickoff()  # HIGH: Autonomous execution 