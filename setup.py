from setuptools import setup, find_packages

setup(
    name="agent_security",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
        "pyyaml>=6.0.1",
        "astroid>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "agent-security=agent_security.cli:main",
        ],
    },
) 