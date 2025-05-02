# Agent Security Scanner

A command-line tool designed to scan LLM agent configurations and code (supporting LangChain, AutoGen, YAML, and Python files) to identify potential security risks and vulnerabilities. It analyzes tool usage, permissions, configurations, and code patterns to generate a comprehensive security report.

## Key Features

-   **Broad Framework Support:** Scans configurations and code for popular agent frameworks like LangChain, AutoGen, and **CrewAI**.
-   **Multiple Format Analysis:** Supports direct scanning of Python (`.py`) files and YAML (`.yaml`, `.yml`) configuration files.
-   **Code Intelligence:** Utilizes Abstract Syntax Trees (AST) for deeper, more accurate analysis of Python code to detect risky patterns and function calls.
-   **Configuration Awareness:** Performs pattern matching within YAML files, including checking keys and values for insecure settings.
-   **Git Repository Scanning:** Can directly scan agent configurations hosted in Git repositories.
-   **Comprehensive Risk Detection:** Identifies a wide range of security issues, including dangerous tool usage, potential code execution, file system access risks, network vulnerabilities, insecure configurations, and more (see "What It Scans For" below).
-   **Detailed Reporting:** Generates reports highlighting findings with risk levels (Critical, High, Medium, Low), descriptions, impacts, line numbers, and remediation advice.
-   **Flexible Output:** Provides reports in human-readable console format, JSON (`--output`), and CSV (`--output-csv`).
-   **Risk Explanation:** Offers detailed explanations for different risk levels (`--explain`).
-   **False Positive Management:** Allows ignoring specific findings via a `.agent_security_ignore` file.
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

**CrewAI Specific:**
-   Detection of CrewAI framework usage (`crewai_import`)
-   Identification of Agent definitions (`crewai_agent`)
-   Identification of Task definitions (`crewai_task`)
-   Detection of Crew orchestration (`crewai_crew`)
-   Detection of custom tool definitions using the `@tool` decorator (`crewai_tool_decorator`)
-   Identification of autonomous execution methods (`kickoff()`, `process()`, `run()`)
-   Detection of memory usage in agents that could lead to data persistence issues
-   Identification of system command execution tools
-   Analysis of human-in-the-loop vs. fully autonomous configurations

## CrewAI Security Best Practices

When using CrewAI, consider these security recommendations:

1. **Tool Restrictions**:
   - Limit tools to only those absolutely necessary
   - Avoid tools that execute system commands or arbitrary code
   - Implement input validation for all tool parameters

2. **Human Oversight**:
   - Use `human_in_the_loop=True` for sensitive operations
   - Implement approval steps for critical actions
   - Monitor agent activities and implement circuit breakers

3. **Memory Management**:
   - Sanitize sensitive data from agent memory
   - Use ephemeral memory when possible
   - Implement proper data lifecycle management

4. **Execution Environment**:
   - Run CrewAI agents in isolated containers
   - Implement resource limits (CPU, memory, time)
   - Use least-privilege principles for execution contexts

5. **Input/Output Validation**:
   - Validate all inputs to tasks and tools
   - Sanitize outputs before using them in subsequent operations
   - Implement content filtering for generated text

## Risk Levels

Findings are categorized into the following risk levels:

-   **CRITICAL**: Highest risk. Indicates capabilities like arbitrary code/command execution or unrestricted system access that could lead to full compromise. Requires immediate attention.
-   **HIGH**: Significant risk. Includes capabilities like unrestricted file system or network access, potential for severe data leaks, or use of dangerous configurations.
-   **MEDIUM**: Moderate risk. May involve limited external access (e.g., specific APIs), potential information leakage through logging, or use of tools that require careful configuration.
-   **LOW**: Minimal risk. Typically involves safe, isolated operations like calculations or restricted search.

## Ignoring Findings (False Positives)

You can instruct the scanner to ignore specific findings by creating a file named `.agent_security_ignore` in the root directory of your project (or the directory you are scanning). The scanner will automatically look for this file in the target directory and its parent directories.

### Format

Each line in the `.agent_security_ignore` file should specify a finding to ignore using the following format:

```
<relative_file_path>:<line_number>:<pattern_name>
```

-   `<relative_file_path>`: The path to the file containing the finding, relative to the location of the `.agent_security_ignore` file.
-   `<line_number>`: The exact line number where the finding occurs.
-   `<pattern_name>`: The name of the pattern reported by the scanner (e.g., `ShellTool`, `crewai_tool_decorator`, `verbose_logging`).

### Example `.agent_security_ignore` File

```
# Ignore a specific ShellTool usage in a utility script
utils/admin_scripts.py:42:ShellTool

# Ignore verbose logging in a specific test file
tests/integration/test_data_processing.py:105:verbose_logging

# Ignore a known-safe custom CrewAI tool
agents/custom_tools.py:25:crewai_tool_decorator

# Ignore CrewAI agent in a test file
tests/test_agents.py:15:crewai_agent
```

### Usage Notes

- Lines starting with `#` are treated as comments and ignored.
- Malformed entries will be skipped with a warning.
- The scanner will look for `.agent_security_ignore` in the target directory and all parent directories.
- Relative paths are resolved from the location of the `.agent_security_ignore` file.
- When to use: For intentional, reviewed, and secured uses of potentially risky patterns.

**Note:** Currently, the `.agent_security_ignore` mechanism is supported only when scanning local files and directories. It is **not** yet supported when scanning Git repositories directly via URL.

## Development

This project aims to follow best practices for secure and maintainable code. Contributions are welcome.