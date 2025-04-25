"""
Test file with edge cases and potential security issues.
"""

from langchain.tools import BaseTool
from typing import Optional
import subprocess
import os

# Potentially dangerous custom tool with obfuscated system access
class CustomTool(BaseTool):
    """Custom tool that might evade detection."""
    def __init__(self):
        super().__init__()
        self._cmd = getattr(subprocess, 'run')  # Indirect reference to subprocess
        self._sys = __import__('os')  # Dynamic import
    
    def _execute(self, cmd: str) -> str:
        """Hidden execution method."""
        return self._cmd(cmd, shell=True, capture_output=True).stdout.decode()

# Tool with mixed risk levels
class HybridTool(BaseTool):
    """Tool with both safe and unsafe capabilities."""
    def __init__(self):
        super().__init__()
        self.safe_mode = True
    
    def run(self, input_str: str) -> str:
        if self.safe_mode:
            return str(eval(input_str))  # Calculator (Low risk)
        else:
            return os.system(input_str)  # Shell (High risk)

# Tool with conditional imports
try:
    from langchain.tools import ShellTool
    shell_tool = ShellTool()
except ImportError:
    shell_tool = CustomTool()  # Fallback to custom implementation

# Tool with dynamic capability loading
class DynamicTool:
    """Tool that loads capabilities at runtime."""
    def __init__(self):
        self.capabilities = {}
    
    def load_capability(self, name: str):
        if name == "shell":
            self.capabilities[name] = lambda cmd: os.system(cmd)
        elif name == "file":
            self.capabilities[name] = lambda path: open(path).read()

# Configuration with hidden risks
config = {
    "tools": {
        "safe_calculator": HybridTool(),  # Looks safe but can be unsafe
        "dynamic_tool": DynamicTool(),  # Loads risky capabilities at runtime
        "custom_tool": CustomTool(),  # Obfuscated system access
    },
    "settings": {
        "safe_mode": True,  # Can be changed at runtime
        "allowed_imports": ["os", "sys", "subprocess"],  # Risky imports
        "blocked_commands": ["rm", "del", "format"],  # Incomplete blocklist
    }
}

# Initialize tools with potential risks
tools = []
for name, tool in config["tools"].items():
    if isinstance(tool, DynamicTool):
        tool.load_capability("shell")  # Loads risky capability
    tools.append(tool)

# Example of potential security bypass
if config["settings"]["safe_mode"]:
    hybrid_tool = config["tools"]["safe_calculator"]
    hybrid_tool.safe_mode = False  # Bypass safety check 