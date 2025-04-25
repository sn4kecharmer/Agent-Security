# Agent Security Scanner

A CLI tool that scans LLM agent configurations (LangChain, AutoGen, YAML, or Python code) and outputs a security report.

## Features

- Detects potentially risky behaviors or permissions in AI agents
- Analyzes tool usage, inputs/outputs, and sensitive actions
- Supports multiple configuration formats (Python, YAML)
- Generates detailed security reports with risk scoring
- Can be integrated into CI/CD pipelines
- Improved Python file scanning using AST parsing for more accurate detection of security issues.
- Enhanced YAML file scanning with line number support and pattern matching in values.
- More general and accurate security patterns for identifying risky tools and configurations.
- Git repository scanning to analyze agent configurations in Git repositories.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m agent_security scan <path-to-config>
```

## Risk Levels

- **HIGH**: Tools that can execute commands, read/write files, or make unrestricted web requests
- **MEDIUM**: Tools with limited access to external systems or data
- **LOW**: Tools that perform safe, isolated operations

## Development

This project follows the SPARC Agentic Development Rules for maintainable and secure code. 