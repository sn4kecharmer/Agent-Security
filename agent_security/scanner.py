"""
Security scanner for LLM agent configurations.
"""

import ast
import yaml
import re
from typing import Dict, List, Optional, Union, Set, Tuple
from pathlib import Path
from .git_scanner import GitScanner
from .models import RiskLevel, SecurityInfo, SecurityFinding, SecurityReport
from .file_scanner import scan_file # scan_file is also defined in this file, this might be a circular import or unused.
from .patterns import (
    TOOL_RISKS, 
    YAML_TOOL_PATTERNS, 
    ACTION_RISK_DESCRIPTIONS,
    AGENT_PATTERNS,
    FRAMEWORK_PATTERNS,
    ENVIRONMENT_PATTERNS,
    TOOL_PATTERNS
)
from .patterns.agent_specific_patterns import AGENT_SECURITY_PATTERNS
from .n8n_scanner import scan_n8n_workflow_content # Added for n8n scanning
import ruamel.yaml
import json # Added for n8n JSON parsing
from datetime import datetime
from tabulate import tabulate
import textwrap
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import os
import logging

# Set up logger
logger = logging.getLogger("agent_security")

# --- False Positive Handling ---
IGNORE_FILE_NAME = ".agent_security_ignore"

def load_ignored_findings(base_path: Path) -> Set[Tuple[str, int, str]]:
    """Loads ignored findings from the ignore file."""
    ignored = set()
    ignore_file_path = base_path / IGNORE_FILE_NAME
    if not ignore_file_path.is_file():
        # Try searching upwards for the ignore file if not in the immediate base path
        current_dir = base_path.resolve()
        while current_dir != current_dir.parent:
            potential_path = current_dir / IGNORE_FILE_NAME
            if potential_path.is_file():
                ignore_file_path = potential_path
                break
            current_dir = current_dir.parent

    if ignore_file_path.is_file():
        try:
            with open(ignore_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(':', 2)
                    if len(parts) == 3:
                        file, line_num_str, pattern = parts
                        try:
                            # Convert line number to int
                            line_num = int(line_num_str)
                            # Store the file path relative to the ignore file's directory
                            file_path = Path(file)
                            if not file_path.is_absolute():
                                file_path = ignore_file_path.parent / file_path
                            relative_file = str(file_path.relative_to(ignore_file_path.parent))
                            ignored.add((relative_file, line_num, pattern))
                        except (ValueError, TypeError):
                            logger.warning(f"Skipping invalid ignore entry: {line}")
                    else:
                        logger.warning(f"Skipping malformed ignore entry: {line}")
        except IOError as e:
            logger.warning(f"Could not read ignore file {ignore_file_path}: {e}")
    return ignored

def is_finding_ignored(finding: SecurityFinding, ignored_set: Set[Tuple[str, int, str]], base_path: Path) -> bool:
    """
    Check if a finding should be ignored based on the ignore set.
    
    Args:
        finding: The security finding to check
        ignored_set: Set of ignored findings
        base_path: The base path from which the scan was initiated
        
    Returns:
        bool: True if the finding should be ignored
    """
    try:
        # Resolve both paths to their canonical form
        finding_path = Path(finding.file_path).resolve(strict=True)
        base_path = base_path.resolve(strict=True)
        
        # Get relative path from base_path
        try:
            relative_path = str(finding_path.relative_to(base_path))
        except ValueError:
            # If finding_path is not under base_path, use the original path
            relative_path = str(finding_path)
            
        # Check if this finding matches any ignored pattern
        for pattern, line, path in ignored_set:
            if (pattern == finding.pattern and 
                (line is None or line == finding.line_number) and
                (path is None or path == relative_path)):
                return True
                
        return False
    except Exception as e:
        logger.error(f"Error checking if finding is ignored: {sanitize_error(e)}")
        return False
# --- End False Positive Handling ---

# --- Risk Description Enhancement Helpers ---

def GET_allowed_actions(
    pattern_details: Optional[SecurityInfo],
    content_context: Optional[str],
    pattern_name: Optional[str]
) -> List[str]:
    """
    Infers allowed actions based on pattern details or content context.
    """
    actions: List[str] = []
    if pattern_details and pattern_details.allowed_actions:
        actions.extend(pattern_details.allowed_actions)

    # If actions are still empty or more inference is needed,
    # use content_context and pattern_name.
    if content_context:
        # Basic inference examples (can be expanded significantly)
        if "os.system(" in content_context or \
           "subprocess.call(" in content_context or \
           "subprocess.run(" in content_context:
            if "execute_shell_command" not in actions:
                actions.append("execute_shell_command")
        
        if "open(" in content_context:
            # Simplistic check for file read/write, can be made more robust
            if ".write(" in content_context or "mode='w'" in content_context or "mode='a'" in content_context:
                 if "write_local_files" not in actions:
                    actions.append("write_local_files")
            elif ".read(" in content_context or "mode='r'" in content_context or (not "mode=" in content_context and not ".write" in content_context and not ".append" in content_context): # Default to read if no mode or write/append
                 if "read_local_files" not in actions:
                    actions.append("read_local_files")

        if "requests.get(" in content_context or \
           "requests.post(" in content_context or \
           "urllib.request.urlopen(" in content_context:
            if "unrestricted_api_call" not in actions:
                actions.append("unrestricted_api_call")
        
        # TODO: Add more sophisticated inference logic based on regex match groups from patterns,
        # or specific keywords related to pattern_name if it's a custom tool.

    return list(set(actions)) # Return unique actions

def GET_contextual_risk_for_action(action_name: str) -> Optional[str]:
    """
    Retrieves a predefined risk description for a given action.
    """
    return ACTION_RISK_DESCRIPTIONS.get(action_name)

# --- End Risk Description Enhancement Helpers ---

def scan_python_file(file_path: str, ignored_findings: Set[Tuple[str, int, str]], base_path: Path) -> SecurityReport:
    """
    Scan a Python file for potential security issues, skipping ignored findings.
    """
    report = SecurityReport(
        findings=[],
        overall_risk=RiskLevel.LOW,
        file_path=file_path,
        timestamp=datetime.now().isoformat()
    )
    processed_patterns = set()  # Track processed patterns to avoid duplicates
    
    try:
        # Read the file content
        with open(file_path, 'r') as f:
            source = f.read()
            source_lines = source.splitlines()
        
        # Parse the AST
        tree = ast.parse(source)
        
        # Helper function to add finding
        def add_finding(pattern_name: str, security_info: SecurityInfo, line_number: int, context: str):
            if (pattern_name, line_number) not in processed_patterns:
                finding = SecurityFinding(
                    pattern=pattern_name,
                    risk_level=security_info.risk_level,
                    line_number=line_number,
                    context=context,
                    security_info=security_info,
                    file_path=file_path
                )
                if not is_finding_ignored(finding, ignored_findings, base_path):
                    report.findings.append(finding)
                processed_patterns.add((pattern_name, line_number))

        # Check all pattern categories
        pattern_categories = [
            AGENT_PATTERNS,
            FRAMEWORK_PATTERNS,
            ENVIRONMENT_PATTERNS,
            TOOL_PATTERNS,
            TOOL_RISKS  # Legacy patterns
        ]

        # Visit all nodes in the AST
        for node in ast.walk(tree):
            # Get node context
            context = ast.get_source_segment(source, node)
            if not context:
                continue

            # Check against all pattern categories
            for patterns in pattern_categories:
                for pattern_name, security_info in patterns.items():
                    if security_info.pattern.search(context):
                        add_finding(pattern_name, security_info, node.lineno, context)

            # Special handling for specific node types
            if isinstance(node, (ast.Str, ast.Constant)) and isinstance(node.value, str):
                # Check string literals
                for patterns in pattern_categories:
                    for pattern_name, security_info in patterns.items():
                        if security_info.pattern.search(node.value):
                            add_finding(pattern_name, security_info, node.lineno, context)

            elif isinstance(node, ast.Call):
                # Check function calls
                func_name = ""
                if hasattr(node.func, 'id'):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # Check function name against patterns
                if func_name:
                    for patterns in pattern_categories:
                        for pattern_name, security_info in patterns.items():
                            if security_info.pattern.search(func_name):
                                add_finding(pattern_name, security_info, node.lineno, context)

        # Calculate overall risk based on findings
        if report.findings:
            risk_levels = [f.risk_level for f in report.findings]
            report.overall_risk = max(risk_levels)

    except Exception as e:
        logger.error(f"Error scanning Python file {file_path}: {e}")
        report.overall_risk = RiskLevel.CRITICAL
        report.metadata = {"error": str(e)}

    return report

def scan_yaml_content(content: str, file_path: str, ignored_findings: Set[Tuple[str, int, str]], base_path: Path) -> SecurityReport:
    """
    Scan YAML content for security issues.
    """
    report = SecurityReport(
        findings=[],
        overall_risk=RiskLevel.LOW,
        file_path=str(file_path),
        timestamp=datetime.now().isoformat()
    )

    try:
        # Parse YAML content with line numbers
        yaml = ruamel.yaml.YAML(typ='safe')
        data = yaml.load(content)
        lines = content.splitlines()
        
        # Create a line map for faster lookups
        line_map = {}
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                key = stripped.split(':')[0].strip()
                line_map[key] = i

        # First check the entire content against patterns
        for patterns in [YAML_TOOL_PATTERNS]:  # We only want to check YAML patterns against the full content
            for pattern_name, security_info in patterns.items():
                matches = list(security_info.pattern.finditer(content))
                for match in matches:
                    # Find the line number by counting newlines before the match
                    line_number = content.count('\n', 0, match.start()) + 1
                    
                    # Get context lines
                    start = max(0, line_number - 2)
                    end = min(len(lines), line_number + 3)
                    context_lines = lines[start:end]

                    finding = SecurityFinding(
                        pattern=pattern_name,
                        risk_level=security_info.risk_level,
                        line_number=line_number,
                        context="\n".join(context_lines),
                        security_info=security_info,
                        file_path=file_path
                    )
                    if not is_finding_ignored(finding, ignored_findings, base_path):
                        report.findings.append(finding)

        def scan_nested(data, path="", parent_key="", line_number=None):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Try to get line number
                    current_line = line_map.get(str(key), line_number)
                    
                    # Get context lines
                    context_lines = []
                    if current_line:
                        start = max(0, current_line - 2)
                        end = min(len(lines), current_line + 2)
                        context_lines = [lines[i] for i in range(start, end)]

                    # Check all pattern categories except YAML_TOOL_PATTERNS (already checked above)
                    pattern_categories = [
                        AGENT_PATTERNS,
                        FRAMEWORK_PATTERNS,
                        ENVIRONMENT_PATTERNS,
                        TOOL_PATTERNS
                    ]

                    for patterns in pattern_categories:
                        for pattern_name, security_info in patterns.items():
                            # Check both key and value against pattern
                            check_value = str(value) if value is not None else ""
                            if security_info.pattern.search(str(key)) or security_info.pattern.search(check_value):
                                finding = SecurityFinding(
                                    pattern=pattern_name,
                                    risk_level=security_info.risk_level,
                                    line_number=current_line,
                                    context="\n".join(context_lines),
                                    security_info=security_info,
                                    file_path=file_path
                                )
                                if not is_finding_ignored(finding, ignored_findings, base_path):
                                    report.findings.append(finding)

                    # Recursively scan nested structures
                    if isinstance(value, (dict, list)):
                        scan_nested(value, current_path, key, current_line)
            
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    current_path = f"{path}[{i}]"
                    scan_nested(item, current_path, parent_key, line_number)

        # Start scanning from the root
        if data is not None:
            scan_nested(data)
        
        # Calculate overall risk based on findings
        if report.findings:
            risk_levels = [f.risk_level for f in report.findings]
            report.overall_risk = max(risk_levels)
        
    except Exception as e:
        # Check if this is a YAML deserialization error
        error_msg = str(e)
        if "python/object" in error_msg or "!!python" in error_msg or "could not determine a constructor" in error_msg:
            # This is likely an unsafe YAML deserialization issue
            # Create a security finding for it
            yaml_deser_info = SecurityInfo(
                risk_level=RiskLevel.CRITICAL,
                pattern=re.compile(r"!!python"),  # Dummy pattern
                description="Unsafe YAML deserialization",
                impact="Could allow arbitrary code execution through YAML deserialization",
                remediation="Use yaml.safe_load() or explicitly specify SafeLoader",
                severity="🔴",
                confidence="High",
                category="",
                cwe=[],
                owasp=[]
            )
            
            # Try to get the line number from the error message
            line_match = re.search(r"line (\d+)", error_msg)
            line_number = int(line_match.group(1)) if line_match else 1
            
            # Get context lines if possible
            context = ""
            try:
                lines = content.splitlines()
                start = max(0, line_number - 2)
                end = min(len(lines), line_number + 3)
                context = "\n".join(lines[start:end])
            except:
                context = "Error extracting context: " + error_msg
            
            finding = SecurityFinding(
                pattern="unsafe_yaml_deserialization",
                risk_level=RiskLevel.CRITICAL,
                line_number=line_number,
                context=context,
                security_info=yaml_deser_info,
                file_path=file_path
            )
            
            report.findings.append(finding)
            report.overall_risk = RiskLevel.CRITICAL
            logger.info(f"Found unsafe YAML deserialization in {file_path}")
        else:
            logger.error(f"Error scanning YAML file {file_path}: {e}")
            report.overall_risk = RiskLevel.CRITICAL
            report.metadata = {"error": str(e)}
def scan_file(file_path: str, ignored_findings: Set[Tuple[str, int, str]], base_path: Path) -> SecurityReport:
    """
    Scan a file for security issues based on its extension, skipping ignored findings.

    Args:
        file_path: Path to the file to scan
        ignored_findings: Set of findings to ignore
        base_path: The base path from which the scan was initiated

    Returns:
        SecurityReport containing findings
    """
    # Handle relative paths by resolving them against base_path
    file_path = Path(file_path)
    if not file_path.is_absolute():
        file_path = base_path / file_path
        
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
        
    # Validate that file_path is within base_path
    try:
        file_path = file_path.resolve(strict=True)
        base_path = base_path.resolve(strict=True)
        
        # Special case: If file_path is directly under base_path/examples, allow it
        examples_dir = base_path / 'examples'
        if not (str(file_path).startswith(str(base_path)) or 
                (examples_dir.exists() and str(file_path).startswith(str(examples_dir)))):
            raise ValueError(f"File {file_path} is outside the base directory {base_path}")
    except Exception as e:
        raise ValueError(f"Path validation failed: {e}")

    if file_path.suffix == '.py':
        return scan_python_file(str(file_path), ignored_findings, base_path)
    elif file_path.suffix in ['.yaml', '.yml']:
        with open(file_path, 'r', encoding='utf-8') as f: # Specify encoding
            content = f.read()
        return scan_yaml_content(content, str(file_path), ignored_findings, base_path)
    elif file_path.suffix == '.json': # Added for n8n workflow files
        with open(file_path, 'r', encoding='utf-8') as f: # Specify encoding
            content = f.read()
        return scan_n8n_workflow_content(content, str(file_path), ignored_findings, base_path)
    else:
        # For unsupported file types, return an empty report
        # logger.debug(f"Unsupported file type: {file_path}, skipping.")
        return SecurityReport(
            findings=[],
            overall_risk=RiskLevel.LOW,
            file_path=str(file_path),
            timestamp=datetime.now().isoformat()
        )

def print_report(report: SecurityReport):
    """
    Print a formatted security report, grouped by file with no column truncation.
    
    Args:
        report: SecurityReport to print
    """
    console = Console()
    
    if not report.findings:
        console.print("\nNo vulnerabilities found.")
        return

    # Group findings by file
    findings_by_file = {}
    for finding in report.findings:
        file_path = finding.file_path
        if file_path not in findings_by_file:
            findings_by_file[file_path] = []
        findings_by_file[file_path].append(finding)

    # Get the scan directory path
    scan_dir = Path(os.getcwd())

    # Process each file's findings separately
    for file_path, file_findings in findings_by_file.items():
        # Get relative path from scan directory
        try:
            path = Path(file_path)
            if path.is_absolute():
                try:
                    file_display = str(path.relative_to(scan_dir))
                except ValueError:
                    file_display = path.name
            else:
                file_display = str(path)
        except Exception:
            file_display = Path(file_path).name

        # Create table for this file
        console.print(f"\n[bold]Findings for: [cyan]{file_display}[/cyan][/bold]\n")
        
        table = Table(
            show_header=True,
            header_style="bold",
            expand=True,
            show_lines=True,
            padding=(0, 1)
        )
        
        # Add columns without width constraints
        table.add_column("Line", style="dim", justify="right")
        table.add_column("Description", style="white")
        table.add_column("Evidence", style="bright_black")
        table.add_column("Remediation", style="green")
        table.add_column("Risk Level", style="yellow")

        # Sort findings by risk level (highest first)
        risk_level_order = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1
        }
        sorted_findings = sorted(
            file_findings,
            key=lambda x: risk_level_order.get(x.risk_level, 0),
            reverse=True
        )

        for finding in sorted_findings:
            # Format context lines
            context_lines = []
            if finding.context:
                lines = finding.context.split('\n')
                for line in lines:
                    cleaned_line = re.sub(r'^Line \d+:\s*', '', line.strip())
                    if cleaned_line:
                        context_lines.append(cleaned_line)

            # Add row with proper styling based on risk level
            risk_style = {
                RiskLevel.CRITICAL: "bold red",
                RiskLevel.HIGH: "bold yellow",
                RiskLevel.MEDIUM: "bold magenta",
                RiskLevel.LOW: "bold blue"
            }.get(finding.risk_level, "white")

            table.add_row(
                str(finding.line_number) if finding.line_number else "N/A",
                finding.security_info.description,
                "\n".join(context_lines),
                finding.security_info.remediation,
                Text(finding.risk_level.name, style=risk_style)
            )

        console.print(table)
    
    console.print()  # Add spacing after all tables

def main():
    """
    Main entry point for the scanner.
    """
    import sys
    import glob
    from pathlib import Path
    
    # Handle both direct script execution and module execution
    args = sys.argv[1:]
    
    # If run as module (python -m agent_security scan path)
    if len(args) >= 2 and args[0] == 'scan':
        path = args[1]
    # If run directly (python scanner.py path)
    elif len(args) >= 1:
        path = args[0]
    else:
        logger.info("Usage: python -m agent_security scan <path>")
        logger.info("   or: python scanner.py <path>")
        sys.exit(1)
    
    try:
        base_path = Path(path).resolve()
        if not base_path.exists():
            logger.error(f"Path not found: {path}")
            sys.exit(1)
        
        # Load ignored findings
        ignored_findings = load_ignored_findings(base_path)
        
        if base_path.is_file():
            # Scan a single file
            report = scan_file(str(base_path), ignored_findings, base_path.parent)
            print_report(report)
            return report  # Return report for API usage
        else:
            # Create a combined report for directory scanning
            combined_report = SecurityReport(
                findings=[],
                overall_risk=RiskLevel.LOW,
                file_path=str(base_path),
                timestamp=datetime.now().isoformat()
            )
            
            # Scan all Python, YAML, and JSON files in the directory
            for ext in ['*.py', '*.yaml', '*.yml', '*.json']: # Added *.json
                for file_path_str in glob.glob(str(base_path / '**' / ext), recursive=True):
                    file_path = Path(file_path_str)
                    # Ensure we are not picking up files from .git or other VCS directories, or node_modules etc.
                    if any(part.startswith('.') for part in file_path.parts) or 'node_modules' in file_path.parts:
                        logger.debug(f"Skipping potentially hidden or vendor directory: {file_path}")
                        continue
                    try:
                        file_report = scan_file(str(file_path), ignored_findings, base_path) # Use str(file_path)
                        if file_report.findings:  # Only add reports that have findings
                            logger.info(f"Found {len(file_report.findings)} issues in {file_path_str}")
                            combined_report.findings.extend(file_report.findings)
                            if file_report.overall_risk > combined_report.overall_risk:
                                combined_report.overall_risk = file_report.overall_risk
                    except Exception as e:
                        logger.error(f"Error scanning file {file_path_str}: {e}")
            
            # Print findings if any were found
            if combined_report.findings:
                print_report(combined_report)
            else:
                logger.info("\nNo vulnerabilities found.")
                
            return combined_report  # Return report for API usage
                
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        sys.exit(1)
        return None

if __name__ == '__main__':
    main()

# Global flag for git support
HAS_GIT_SUPPORT = False

def scan_git_repository(repo_url: str, branch: str = None) -> SecurityReport:
    """
    Scan a Git repository for potential security issues.
    
    Args:
        repo_url: URL of the Git repository
        branch: Optional branch to scan
        
    Returns:
        SecurityReport containing findings
    """
    # Lazy import git support only when needed
    try:
        from .git_scanner import GitScanner
        scanner = GitScanner(repo_url, branch)
        return scanner.scan()
    except ImportError:
        raise ValueError("Git support is not available in this environment. Please install git to use this feature.")

class SecurityScanner:
    """Main scanner class for analyzing agent configurations."""
    
    def __init__(self, base_path: str, ignore_patterns: Optional[List[str]] = None):
        """Initialize scanner with base path and optional ignore patterns."""
        self.base_path = os.path.abspath(base_path)
        self.ignore_patterns = ignore_patterns or []
        self.file_scanner = FileScanner()
        self.max_depth = 10  # Limit directory traversal depth
        self.max_files = 1000  # Limit total files to scan
        self.file_count = 0
        self.current_depth = 0
        
    def scan(self) -> SecurityReport:
        """Scan the target path for security issues."""
        logger.info(f"Starting security scan of {self.base_path}")
        report = SecurityReport()
        
        try:
            if not os.path.exists(self.base_path):
                raise FileNotFoundError(f"Path not found: {self.base_path}")
                
            if not os.path.isdir(self.base_path):
                # Single file scan
                self._scan_file(self.base_path, report)
            else:
                # Directory scan
                self._scan_directory(self.base_path, report)
                
            return report
            
        except Exception as e:
            logger.error(f"Error during scan: {sanitize_error(e)}")
            raise
            
    def _scan_directory(self, directory: str, report: SecurityReport) -> None:
        """Recursively scan a directory."""
        if self.current_depth > self.max_depth:
            logger.warning(f"Maximum directory depth reached: {directory}")
            return
            
        if self.file_count >= self.max_files:
            logger.warning("Maximum file count reached")
            return
            
        self.current_depth += 1
        try:
            for root, dirs, files in os.walk(directory):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if self.file_count >= self.max_files:
                        return
                        
                    # Skip hidden files
                    if file.startswith('.'):
                        continue
                        
                    file_path = os.path.join(root, file)
                    self._scan_file(file_path, report)
                    self.file_count += 1
        finally:
            self.current_depth -= 1

    def validate_file_path(self, file_path: str) -> str:
        """Validate and sanitize file path."""
        try:
            # Convert to absolute path
            abs_path = os.path.abspath(file_path)
            
            # Check if path exists
            if not os.path.exists(abs_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Check if path is under base path
            if not abs_path.startswith(self.base_path):
                raise ValueError(f"File path {file_path} is outside base directory")
            
            # Check file permissions
            if not os.access(abs_path, os.R_OK):
                raise PermissionError(f"No read permission for file: {file_path}")
            
            return abs_path
        
        except Exception as e:
            logger.error(f"Path validation error: {sanitize_error(e)}")
            raise

    def validate_file_content(self, content: str, file_path: str) -> None:
        """Validate file content."""
        try:
            # Check for null bytes
            if '\0' in content:
                raise ValueError(f"File {file_path} contains null bytes")
            
            # Check for binary content
            if not all(ord(c) < 128 for c in content):
                raise ValueError(f"File {file_path} appears to be binary")
            
            # Check for maximum line length
            max_line_length = 10000
            for i, line in enumerate(content.splitlines(), 1):
                if len(line) > max_line_length:
                    raise ValueError(f"Line {i} in {file_path} exceeds maximum length of {max_line_length}")
                
        except Exception as e:
            logger.error(f"Content validation error: {sanitize_error(e)}")
            raise

    def _scan_file(self, file_path: str, report: SecurityReport) -> None:
        """Scan a single file for security issues."""
        try:
            # Validate file path
            abs_path = self.validate_file_path(file_path)
            
            # Skip ignored files
            if self.is_finding_ignored(abs_path):
                logger.debug(f"Skipping ignored file: {abs_path}")
                return
            
            # Read and validate file content
            with open(abs_path, 'r') as f:
                content = f.read()
            self.validate_file_content(content, abs_path)
            
            # Scan file based on type
            if abs_path.endswith('.py'):
                findings = self.file_scanner.scan_python_file(abs_path)
            elif abs_path.endswith(('.yaml', '.yml')):
                findings = self.file_scanner.scan_yaml_file(abs_path)
            else:
                logger.debug(f"Skipping unsupported file type: {abs_path}")
                return
            
            # Add findings to report
            for finding in findings:
                if not self.is_finding_ignored(finding):
                    report.add_finding(finding)
                
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {sanitize_error(e)}")
            raise