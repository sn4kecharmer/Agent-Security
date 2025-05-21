# Agent Security Scanner

A command-line tool designed to scan LLM agent configurations and code (supporting LangChain, AutoGen, YAML, and Python files) to identify potential security risks and vulnerabilities. It analyzes tool usage, permissions, configurations, and code patterns to generate a comprehensive security report.

## License Notice

This software is proprietary and requires explicit written permission for any use, modification, or distribution. Please contact the copyright holders for licensing information.

## Key Features

-   **Broad Framework Support:** Scans configurations and code for popular agent frameworks like LangChain, AutoGen, and CrewAI.
-   **Multiple Format Analysis:** Supports direct scanning of Python (`.py`) files and YAML (`.yaml`, `.yml`) configuration files.
-   **Code Intelligence:** Utilizes Abstract Syntax Trees (AST) for deeper, more accurate analysis of Python code.
-   **Configuration Awareness:** Performs pattern matching within YAML files for insecure settings.
-   **Git Repository Scanning:** Can directly scan agent configurations hosted in Git repositories.
-   **Comprehensive Risk Detection:** Identifies security issues including dangerous tool usage, code execution, file system access, and network vulnerabilities.
-   **Detailed Reporting:** Generates reports with risk levels (Critical, High, Medium, Low), descriptions, and remediation advice.
-   **Flexible Output:** Provides reports in console format, JSON (`--output`), and CSV (`--output-csv`).
-   **False Positive Management:** Allows ignoring specific findings via a `.agent_security_ignore` file.
-   **Enhanced Security:** Implements safe YAML loading, path validation, and improved pattern detection.

## Installation

```bash
# Clone the repository (if you haven't already)
# git clone <repository-url>
# cd agent-security-scanner

# Install dependencies
pip install -r requirements.txt

# Optional: Install the package locally for easier CLI access
# pip install .
```

## Usage

```bash
python -m agent_security.cli <target> [options]
```

**Arguments:**
-   `<target>`: (Required) The file path or Git repository URL to scan.

**Options:**
-   `--branch <branch_name>`: Specify a branch when scanning a Git repository.
-   `--output <output.json>`: Output the report in JSON format.
-   `--output-csv <report.csv>`: Output the findings in CSV format.
-   `--explain`: Include detailed explanations of risk levels.
-   `--json-stdout`: Output the report in JSON format to stdout.
-   `-f, --format {json,table}`: Specify the output format.

**Examples:**

```bash
# Scan a single Python file
python -m agent_security.cli examples/langchain_agent.py

# Scan a YAML file and explain risks
python -m agent_security.cli examples/test_agent.yaml --explain

# Scan a Git repository
python -m agent_security.cli https://github.com/example/agent-repo

# Save report as JSON
python -m agent_security.cli examples/autogen_config.py --output report.json
```

## What It Scans For

The scanner checks for various security vulnerabilities and risky patterns, including:

**Code Execution & System Access:**
-   Arbitrary Shell Command Execution
-   Arbitrary Python Code Execution
-   Path traversal vulnerabilities
-   Unsafe YAML deserialization

**File System Access:**
-   Unrestricted file operations
-   Temporary file storage risks
-   Insecure file permissions

**Network Access:**
-   Unrestricted web requests
-   Server-Side Request Forgery (SSRF) risks
-   Missing rate limiting
-   Insecure API endpoints

**Secrets Management:**
-   Hardcoded API keys and credentials
-   Insecure credential storage
-   Exposed environment variables

**Input Validation & Injection:**
-   Lack of input validation
-   Command Injection risks
-   Regex denial of service vulnerabilities

**Insecure Configurations:**
-   Overly permissive tool access
-   Disabled sandboxing
-   Verbose logging
-   Missing authentication controls
-   High LLM temperature settings

## Risk Levels

-   **CRITICAL**: Highest risk. Arbitrary code execution or unrestricted system access.
-   **HIGH**: Significant risk. Unrestricted file system or network access.
-   **MEDIUM**: Moderate risk. Limited external access or potential information leakage.
-   **LOW**: Minimal risk. Safe, isolated operations.

## Ignoring Findings

Create a `.agent_security_ignore` file to ignore specific findings:

```
<relative_file_path>:<line_number>:<pattern_name>
```

Example:
```
# Ignore a specific ShellTool usage
utils/admin_scripts.py:42:ShellTool

# Ignore verbose logging
tests/test_data_processing.py:105:verbose_logging
```

**Note:** The ignore mechanism is currently supported only for local files and directories.

## Docker Usage

You can also run the scanner using Docker:

```bash
# Build the Docker image
docker build -t agent-security .

# Scan a directory
docker run -v /path/to/your/code:/scan agent-security /scan [options]

# Scan a single file
docker run -v /path/to/your/file.py:/scan/file.py agent-security file.py [options]

# Output to a file (the output will be created in your mounted volume)
docker run -v /path/to/your/code:/scan agent-security /scan --output-csv report.csv

# Scan a Git repository
docker run agent-security https://github.com/example/agent-repo --branch main
```

Using Docker ensures that the scanner runs in an isolated environment with all dependencies properly installed.

For CI/CD pipelines or frequent scanning, you can use the included helper script:

```bash
# Make the script executable (first time only)
chmod +x docker-scan.sh

# Build the image and scan a directory
./docker-scan.sh --build ./your-project

# Scan a Git repository
./docker-scan.sh https://github.com/example/agent-repo

# Scan with options
./docker-scan.sh ./your-project --output-csv results.csv
```

## Development

This project aims to follow best practices for secure and maintainable code. Contributions are welcome.