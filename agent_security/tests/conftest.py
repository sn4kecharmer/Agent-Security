"""
Common test fixtures for agent_security tests.
"""

import pytest
import os
import tempfile
from pathlib import Path
import yaml
from agent_security.models import RiskLevel, SecurityInfo, SecurityFinding, SecurityReport
from datetime import datetime
import re

# Paths to fixture files
FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.fixture
def safe_yaml_path():
    """Return path to safe YAML config fixture."""
    return FIXTURES_DIR / "safe_config.yaml"

@pytest.fixture
def risky_yaml_path():
    """Return path to risky YAML config fixture."""
    return FIXTURES_DIR / "risky_config.yaml"

@pytest.fixture
def safe_agent_path():
    """Return path to safe Python agent fixture."""
    return FIXTURES_DIR / "safe_agent.py"

@pytest.fixture
def risky_agent_path():
    """Return path to risky Python agent fixture."""
    return FIXTURES_DIR / "risky_agent.py"

@pytest.fixture
def safe_yaml_content(safe_yaml_path):
    """Return content of safe YAML config."""
    with open(safe_yaml_path, 'r') as f:
        return f.read()

@pytest.fixture
def risky_yaml_content(risky_yaml_path):
    """Return content of risky YAML config."""
    with open(risky_yaml_path, 'r') as f:
        return f.read()

@pytest.fixture
def safe_agent_content(safe_agent_path):
    """Return content of safe Python agent."""
    with open(safe_agent_path, 'r') as f:
        return f.read()

@pytest.fixture
def risky_agent_content(risky_agent_path):
    """Return content of risky Python agent."""
    with open(risky_agent_path, 'r') as f:
        return f.read()

@pytest.fixture
def temp_directory():
    """Create a temporary directory for tests and clean it up after."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)

@pytest.fixture
def temp_python_file():
    """Create a temporary Python file for tests and clean it up after."""
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
        yield Path(temp.name)
        # Clean up
        if os.path.exists(temp.name):
            os.unlink(temp.name)

@pytest.fixture
def temp_yaml_file():
    """Create a temporary YAML file for tests and clean it up after."""
    with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as temp:
        yield Path(temp.name)
        # Clean up
        if os.path.exists(temp.name):
            os.unlink(temp.name)

@pytest.fixture
def sample_security_info():
    """Return a sample SecurityInfo object."""
    return SecurityInfo(
        risk_level=RiskLevel.HIGH,
        description="Test security issue",
        impact="Could lead to security problems",
        remediation="Fix it by doing X",
        pattern=re.compile(r"risky_pattern"),
        confidence="High",
        category="Test Category"
    )

@pytest.fixture
def sample_security_finding(sample_security_info):
    """Return a sample SecurityFinding object."""
    return SecurityFinding(
        pattern="risky_pattern",
        risk_level=RiskLevel.HIGH,
        line_number=10,
        context="risky_pattern('test')",
        security_info=sample_security_info,
        file_path="test_file.py"
    )

@pytest.fixture
def sample_security_report(sample_security_finding):
    """Return a sample SecurityReport object."""
    return SecurityReport(
        findings=[sample_security_finding],
        overall_risk=RiskLevel.HIGH,
        file_path="test_file.py",
        timestamp=datetime.now().isoformat()
    )

@pytest.fixture
def ignore_file_content():
    """Return sample content for a .agent_security_ignore file."""
    return """
# This is a comment
test_file.py:10:risky_pattern
other_file.py:25:another_pattern
"""

@pytest.fixture
def create_ignore_file(temp_directory):
    """Create a .agent_security_ignore file in the specified directory."""
    def _create_ignore_file(content):
        ignore_path = temp_directory / ".agent_security_ignore"
        with open(ignore_path, 'w') as f:
            f.write(content)
        return ignore_path
    return _create_ignore_file 