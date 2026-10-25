from setuptools import find_packages, setup

setup(
    name="agent_security",
    version="1.1.0",
    description="Static security checks for LLM agents and MCP configurations",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
        "pyyaml>=6.0.1",
        "ruamel.yaml>=0.17.40",
        "astroid>=3.0.0",
        "gitpython>=3.1.40",
        "tabulate",
    ],
    extras_require={"dev": ["pytest", "pytest-cov", "pytest-mock"]},
    entry_points={
        "console_scripts": [
            "agent-security=agent_security.cli:entrypoint",
        ],
    },
)
