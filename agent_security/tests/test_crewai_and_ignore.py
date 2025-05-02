import pytest
import tempfile
import os
from pathlib import Path
from agent_security.scanner import scan_python_file, load_ignored_findings, is_finding_ignored
from agent_security.models import RiskLevel, SecurityFinding, SecurityInfo

# Sample CrewAI code for testing
CREWAI_SAMPLE = """
from crewai import Agent, Task, Crew, Tool
from crewai.tools import tool
from crewai.memory import Memory

# Define a tool using the decorator
@tool
def search_web(query: str) -> str:
    \"\"\"Search the web for information\"\"\"
    return f"Results for {query}"

# Define another tool with parameters
@tool(name="calculator")
def calculate(expression: str) -> float:
    \"\"\"Calculate a mathematical expression\"\"\"
    return eval(expression)  # Note: eval is risky

# Define a process execution tool - high risk
@tool
def execute_command(command: str) -> str:
    \"\"\"Execute a system command\"\"\"
    import subprocess
    return subprocess.check_output(command, shell=True).decode()

# Define an agent with memory
researcher = Agent(
    name="Researcher",
    goal="Research information",
    backstory="You are an expert researcher",
    verbose=True,
    memory=Memory()
)

# Define a task
research_task = Task(
    description="Research a topic",
    expected_output="Research findings",
    agent=researcher
)

# Create a crew
crew = Crew(
    agents=[researcher],
    tasks=[research_task],
    verbose=True
)

# Execute the crew autonomously
result = crew.kickoff()
"""

# Sample with human-in-the-loop configuration
CREWAI_HUMAN_IN_LOOP = """
from crewai import Agent, Task, Crew, Tool
from crewai.tools import tool

# Define an agent
researcher = Agent(
    name="Researcher",
    goal="Research information",
    backstory="You are an expert researcher",
    verbose=True,
    allow_delegation=False
)

# Define a task
research_task = Task(
    description="Research a topic",
    expected_output="Research findings",
    agent=researcher,
    human_input=True
)

# Create a crew with human oversight
crew = Crew(
    agents=[researcher],
    tasks=[research_task],
    verbose=True,
    process=True,
    human_in_the_loop=True
)

# Execute the crew with human oversight
result = crew.process()
"""

def test_crewai_patterns():
    """Test detection of CrewAI patterns in Python code."""
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
        temp.write(CREWAI_SAMPLE.encode('utf-8'))
        temp_path = temp.name
    
    try:
        # Create an empty set for ignored findings and use the temp file's directory as base_path
        ignored_findings = set()
        base_path = Path(temp_path).parent
        
        # Scan the file
        report = scan_python_file(temp_path, ignored_findings, base_path)
        
        # Verify findings
        assert len(report.findings) >= 8, "Should detect at least 8 issues"
        
        # Check for specific patterns
        patterns_found = [finding.pattern for finding in report.findings]
        
        # Check for CrewAI import
        assert "crewai_import" in patterns_found, "Should detect CrewAI import"
        
        # Check for CrewAI agent
        assert "crewai_agent" in patterns_found, "Should detect CrewAI Agent"
        
        # Check for CrewAI task
        assert "crewai_task" in patterns_found, "Should detect CrewAI Task"
        
        # Check for CrewAI crew
        assert "crewai_crew" in patterns_found, "Should detect CrewAI Crew"
        
        # Check for CrewAI autonomous execution
        assert "crewai_autonomous" in patterns_found, "Should detect autonomous execution"
        
        # Check for CrewAI memory usage
        assert "crewai_memory" in patterns_found, "Should detect memory usage"
        
        # Check for CrewAI tool decorator
        assert "crewai_tool_decorator" in patterns_found, "Should detect CrewAI tool decorator"
        
        # Check for unsafe code execution (eval)
        assert any("unsafe_code_execution" in p for p in patterns_found), "Should detect unsafe code execution"
        
        # Verify risk level
        assert report.overall_risk == RiskLevel.CRITICAL, "Overall risk should be CRITICAL due to eval usage"
    
    finally:
        # Clean up the temporary file
        os.unlink(temp_path)

def test_human_in_loop_patterns():
    """Test detection of human-in-the-loop patterns which should have lower risk."""
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
        temp.write(CREWAI_HUMAN_IN_LOOP.encode('utf-8'))
        temp_path = temp.name
    
    try:
        # Create an empty set for ignored findings
        ignored_findings = set()
        base_path = Path(temp_path).parent
        
        # Scan the file
        report = scan_python_file(temp_path, ignored_findings, base_path)
        
        # Check for specific patterns
        patterns_found = [finding.pattern for finding in report.findings]
        
        # Should still detect basic patterns
        assert "crewai_import" in patterns_found, "Should detect CrewAI import"
        assert "crewai_agent" in patterns_found, "Should detect CrewAI Agent"
        assert "crewai_task" in patterns_found, "Should detect CrewAI Task"
        assert "crewai_crew" in patterns_found, "Should detect CrewAI Crew"
        
        # Should detect process method
        assert "crewai_autonomous" in patterns_found, "Should detect process method"
        
        # But overall risk should be HIGH, not CRITICAL (since no eval or shell commands)
        assert report.overall_risk == RiskLevel.HIGH, "Overall risk should be HIGH for human-in-the-loop configuration"
        
    finally:
        # Clean up the temporary file
        os.unlink(temp_path)

def test_ignore_file_mechanism():
    """Test that the .agent_security_ignore file correctly filters findings."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a directory structure
        base_path = Path(temp_dir)
        
        # Create a Python file with CrewAI code
        py_file_path = base_path / "test_agent.py"
        with open(py_file_path, 'w') as f:
            f.write(CREWAI_SAMPLE)
        
        # First scan without ignore file
        ignored_findings = set()
        report_without_ignore = scan_python_file(str(py_file_path), ignored_findings, base_path)
        initial_findings_count = len(report_without_ignore.findings)
        
        # Get line numbers for specific patterns to ignore
        crewai_import_line = next(f.line_number for f in report_without_ignore.findings 
                                if f.pattern == "crewai_import")
        
        tool_decorator_line = next(f.line_number for f in report_without_ignore.findings 
                                 if f.pattern == "crewai_tool_decorator")
        
        # Create an ignore file
        ignore_file_path = base_path / ".agent_security_ignore"
        with open(ignore_file_path, 'w') as f:
            f.write(f"# Ignore CrewAI import\n")
            f.write(f"test_agent.py:{crewai_import_line}:crewai_import\n")
            f.write(f"\n# Ignore tool decorator\n")
            f.write(f"test_agent.py:{tool_decorator_line}:crewai_tool_decorator\n")
        
        # Load ignored findings
        ignored_set = load_ignored_findings(base_path)
        
        # Verify ignored findings were loaded correctly
        assert len(ignored_set) == 2, "Should have loaded 2 ignored findings"
        
        # Scan again with ignore file
        report_with_ignore = scan_python_file(str(py_file_path), ignored_set, base_path)
        
        # Verify findings were ignored
        assert len(report_with_ignore.findings) == initial_findings_count - 2, \
               "Should have 2 fewer findings with ignore file"
        
        # Verify specific patterns were ignored
        patterns_found = [finding.pattern for finding in report_with_ignore.findings]
        assert "crewai_import" not in patterns_found, "crewai_import should be ignored"
        assert "crewai_tool_decorator" not in patterns_found or \
               all(f.line_number != tool_decorator_line for f in report_with_ignore.findings 
                   if f.pattern == "crewai_tool_decorator"), \
               "crewai_tool_decorator should be ignored for the specified line"

def test_is_finding_ignored():
    """Test the is_finding_ignored function directly."""
    # Create a mock finding
    finding = SecurityFinding(
        pattern="test_pattern",
        risk_level=RiskLevel.HIGH,
        line_number=42,
        context="Test context",
        security_info=SecurityInfo(
            risk_level=RiskLevel.HIGH,
            description="Test description",
            impact="Test impact",
            remediation="Test remediation",
            pattern=None  # Not needed for this test
        ),
        file_path="path/to/file.py"
    )
    
    # Create a mock ignored set
    ignored_set = {
        ("path/to/file.py", 42, "test_pattern"),
        ("path/to/other.py", 10, "other_pattern")
    }
    
    # Test with a base path that matches
    base_path = Path(".")
    assert is_finding_ignored(finding, ignored_set, base_path), \
           "Finding should be ignored when it matches an entry in the ignored set"
    
    # Test with a finding that doesn't match
    finding.line_number = 43
    assert not is_finding_ignored(finding, ignored_set, base_path), \
           "Finding should not be ignored when line number doesn't match"
    
    finding.line_number = 42
    finding.pattern = "different_pattern"
    assert not is_finding_ignored(finding, ignored_set, base_path), \
           "Finding should not be ignored when pattern doesn't match"

def test_malformed_ignore_file():
    """Test handling of malformed ignore file entries."""
    with tempfile.TemporaryDirectory() as temp_dir:
        base_path = Path(temp_dir)
        
        # Create a Python file with CrewAI code
        py_file_path = base_path / "test_agent.py"
        with open(py_file_path, 'w') as f:
            f.write(CREWAI_SAMPLE)
        
        # Create a malformed ignore file
        ignore_file_path = base_path / ".agent_security_ignore"
        with open(ignore_file_path, 'w') as f:
            f.write("# This is a comment\n")
            f.write("test_agent.py:10:crewai_import  # Valid entry\n")
            f.write("malformed_entry_no_line_number\n")  # Malformed
            f.write("another:malformed:entry:with:too:many:colons\n")  # Malformed
            f.write("test_agent.py:not_a_number:pattern\n")  # Invalid line number
        
        # Load ignored findings - should only load the valid entry
        ignored_set = load_ignored_findings(base_path)
        
        # Should have loaded only the valid entry
        assert len(ignored_set) == 1, "Should have loaded only the valid ignore entry"
        
        # The valid entry should be properly parsed
        valid_entry = next(iter(ignored_set))
        assert valid_entry[0] == "test_agent.py", "File path should be parsed correctly"
        assert valid_entry[1] == 10, "Line number should be parsed correctly"
        assert valid_entry[2] == "crewai_import", "Pattern should be parsed correctly"

def test_ignore_file_in_parent_directory():
    """Test that ignore files in parent directories are found and used."""
    with tempfile.TemporaryDirectory() as temp_dir:
        base_path = Path(temp_dir)
        
        # Create a nested directory structure
        nested_dir = base_path / "project" / "src"
        nested_dir.mkdir(parents=True, exist_ok=True)
        
        # Create a Python file in the nested directory
        py_file_path = nested_dir / "agent.py"
        with open(py_file_path, 'w') as f:
            f.write(CREWAI_SAMPLE)
        
        # Create an ignore file in the parent directory
        ignore_file_path = base_path / "project" / ".agent_security_ignore"
        with open(ignore_file_path, 'w') as f:
            f.write("src/agent.py:1:crewai_import\n")
        
        # Load ignored findings from the nested directory
        ignored_set = load_ignored_findings(nested_dir)
        
        # Should have found and loaded the ignore file from the parent
        assert len(ignored_set) == 1, "Should have loaded the ignore entry from parent directory"
        
        # Scan the file with the ignored findings
        report = scan_python_file(str(py_file_path), ignored_set, base_path / "project")
        
        # Verify the crewai_import finding was ignored
        patterns_found = [finding.pattern for finding in report.findings]
        assert "crewai_import" not in patterns_found, "crewai_import should be ignored"

if __name__ == "__main__":
    pytest.main(["-xvs", __file__])