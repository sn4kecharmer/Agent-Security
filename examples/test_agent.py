"""
Example agent configuration with various tools to demonstrate the security scanner.
"""

from langchain.tools import ShellTool, PythonREPLTool, RequestsGetTool
from langchain.agents import Tool

# High risk tools
shell_tool = ShellTool()
python_repl = PythonREPLTool()

# Medium risk tools
web_tool = RequestsGetTool()

# Safe tools
def safe_calculator(query: str) -> str:
    """A safe calculator function."""
    try:
        return str(eval(query))
    except:
        return "Invalid expression"

calculator = Tool(
    name="Calculator",
    func=safe_calculator,
    description="A safe calculator that evaluates mathematical expressions"
)

# Agent configuration
tools = [
    shell_tool,
    python_repl,
    web_tool,
    calculator
] 