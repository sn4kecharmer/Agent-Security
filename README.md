# Agent Security Scanner

A command-line tool designed to scan LLM agent configurations and code (supporting LangChain, AutoGen, YAML, and Python files) to identify potential security risks and vulnerabilities. It analyzes tool usage, permissions, configurations, and code patterns to generate a comprehensive security report.

## Key Features

-   **Broad Framework Support:** Scans configurations and code for popular agent frameworks like LangChain and AutoGen.
-   **Multiple Format Analysis:** Supports direct scanning of Python (`.py`) files and YAML (`.yaml`, `.yml`) configuration files.
-   **Code Intelligence:** Utilizes Abstract Syntax Trees (AST) for deeper, more accurate analysis of Python code to detect risky patterns and function calls.
-   **Configuration Awareness:** Performs pattern matching within YAML files, including checking keys and values for insecure settings.
-   **Git Repository Scanning:** Can directly scan agent configurations hosted in Git repositories.
-   **Comprehensive Risk Detection:** Identifies a wide range of security issues, including dangerous tool usage, potential code execution, file system access risks, network vulnerabilities, insecure configurations, and more (see "What It Scans For" below).
-   **Detailed Reporting:** Generates reports highlighting findings with risk levels (Critical, High, Medium, Low), descriptions, impacts, line numbers, and remediation advice.
-   **Flexible Output:** Provides reports in human-readable console format, JSON (`--output`), and CSV (`--output-csv`).
-   **Risk Explanation:** Offers detailed explanations for different risk levels (`--explain`).
-   **CI/CD Integration:** Can be integrated into development pipelines to enforce security checks.

## Installation

```bash
# Clone the repository (if you haven't already)
# git clone <repository-url>
# cd agent-security-scanner

# Install dependencies
pip install -r requirements.txt

# Optional: Install the package locally for easier CLI access
# python setup.py install
# or
# pip install .
```

## Usage

The primary way to use the scanner is via the command line, specifying a target file or Git repository URL.

```bash
python -m agent_security <target> [options]
```

**Arguments:**

-   `<target>`: (Required) The file path (e.g., `examples/test_agent.py`, `config.yaml`) or the Git repository URL (e.g., `https://github.com/example/agent-repo`) to scan.

**Options:**

-   `--branch <branch_name>`: Specify a particular branch to scan when providing a Git repository URL.
-   `--output <output.json>`: Output the report in JSON format to the specified file path. If not provided, the report prints to the console.
-   `--output-csv <report.csv>`: Output the findings in CSV format to the specified file path.
-   `--explain`: Include detailed explanations of the detected risk levels in the console output.

**Examples:**

```bash
# Scan a single Python file
python -m agent_security examples/langchain_agent.py

# Scan a single YAML file and explain risks
python -m agent_security examples/test_agent.yaml --explain

# Scan a Git repository (default branch)
python -m agent_security https://github.com/example/agent-repo

# Scan a specific branch of a Git repository
python -m agent_security https://github.com/example/agent-repo --branch develop

# Scan a file and save the report as JSON
python -m agent_security examples/autogen_config.py --output report.json

# Scan a file and save the findings as CSV
python -m agent_security examples/complex_agent.yaml --output-csv findings.csv

# Scan a repository and save findings as CSV
python -m agent_security https://github.com/example/agent-repo --output-csv repo_findings.csv
```

## What It Scans For

The scanner checks for various security vulnerabilities and risky patterns, including:

**Code Execution & System Access:**
-   Arbitrary Shell Command Execution (e.g., `ShellTool`)
-   Arbitrary Python Code Execution (e.g., `PythonREPLTool`, `exec`, `eval`)
-   Use of agents with code execution capabilities (e.g., AutoGen `UserProxyAgent`)

**File System Access:**
-   Unrestricted file reads/writes/deletions (e.g., `file_access`, `read_file`, `write_file`)
-   Access via specific agents (e.g., AutoGen `RetrieveAssistantAgent`)

**Network Access:**
-   Unrestricted web requests (e.g., `RequestsGetTool`, `network_access`)
-   Server-Side Request Forgery (SSRF) risks
-   Unrestricted domain access

**Secrets Management:**
-   Hardcoded API keys, tokens, or passwords in code or configuration (`api_key`, `secret_key`, etc.)

**Input Validation & Injection:**
-   Lack of input validation or sanitization (potential for Prompt Injection, Command Injection)
-   Direct injection of user input into prompts or tools (`PromptTemplate`, `{input}`)
-   Disabled sanitization flags

**Insecure Configurations:**
-   Overly permissive tool access (e.g., `allow_unrestricted_tools: true`)
-   Disabled sandboxing or isolation (`sandboxing: false`)
-   Verbose logging that might expose sensitive data (`verbose: True`, `logging.level: debug`)
-   Missing authentication or authorization controls
-   Use of risky or unscoped LLM models
-   High LLM temperature settings (>0.7)
-   Missing rate limiting or timeouts

**Database Access:**
-   Direct database access capabilities (potential for data leaks or modification)

**Other:**
-   Risky tool descriptions indicating unsafe capabilities
-   Use of temporary storage that might expose data (`/tmp/`)

## Risk Levels

Findings are categorized into the following risk levels:

-   **CRITICAL**: Highest risk. Indicates capabilities like arbitrary code/command execution or unrestricted system access that could lead to full compromise. Requires immediate attention.
-   **HIGH**: Significant risk. Includes capabilities like unrestricted file system or network access, potential for severe data leaks, or use of dangerous configurations.
-   **MEDIUM**: Moderate risk. May involve limited external access (e.g., specific APIs), potential information leakage through logging, or use of tools that require careful configuration.
-   **LOW**: Minimal risk. Typically involves safe, isolated operations like calculations or restricted search.

## Development

This project aims to follow best practices for secure and maintainable code. Contributions are welcome.