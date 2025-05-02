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
from .file_scanner import scan_file
from .patterns import TOOL_RISKS, YAML_TOOL_PATTERNS
import ruamel.yaml
from datetime import datetime
from tabulate import tabulate
import textwrap
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

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
        else: # If loop completes without finding the file
             ignore_file_path = base_path / IGNORE_FILE_NAME # Default back if not found upwards

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
                            # Store relative path for comparison
                            relative_file = str(Path(file).relative_to(ignore_file_path.parent))
                            ignored.add((relative_file, int(line_num_str), pattern))
                        except (ValueError, TypeError):
                            print(f"Warning: Skipping invalid ignore entry: {line}") # Handle potential errors converting line number
                    else:
                         print(f"Warning: Skipping malformed ignore entry: {line}")
        except IOError as e:
            print(f"Warning: Could not read ignore file {ignore_file_path}: {e}")
    return ignored

def is_finding_ignored(finding: SecurityFinding, ignored_set: Set[Tuple[str, int, str]], base_path: Path) -> bool:
    """Checks if a finding is in the ignored set."""
    try:
        # Ensure comparison uses relative paths from the ignore file's perspective
        relative_finding_path = str(Path(finding.file_path).relative_to(base_path))
        return (relative_finding_path, finding.line_number, finding.pattern) in ignored_set
    except ValueError:
        # Handle cases where the finding path might not be relative to the base path
        # This might happen with absolute paths or paths outside the project during git scans
        # For now, we assume such findings are not ignored by a relative ignore file.
        # A more robust solution might involve normalizing paths.
        return False
# --- End False Positive Handling ---


def scan_python_file(file_path: str, ignored_findings: Set[Tuple[str, int, str]], base_path: Path) -> SecurityReport:
    """
    Scan a Python file for potential security issues, skipping ignored findings.

    Args:
        file_path: Path to the Python file
        ignored_findings: Set of findings to ignore
        base_path: The base path from which the scan was initiated (to resolve relative ignore paths)

    Returns:
        SecurityReport containing findings with detailed security information
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
        
        # Parse the AST
        tree = ast.parse(source)
        
        # Visit all nodes in the AST
        for node in ast.walk(tree):
            # Check for imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_base = ""
                if isinstance(node, ast.ImportFrom) and node.module:
                    module_base = node.module
                
                for alias in node.names:
                    module_name = alias.name
                    full_module_name = f"{module_base}.{module_name}" if module_base else module_name

                    # LangChain Check
                    if 'langchain' in full_module_name or module_base == 'langchain':
                        pattern_key = 'langchain'
                        if (pattern_key, node.lineno) not in processed_patterns:
                            context = ast.get_source_segment(source, node)
                            finding = SecurityFinding(
                                pattern=pattern_key,
                                risk_level=TOOL_RISKS[pattern_key].risk_level,
                                line_number=node.lineno,
                                context=context,
                                security_info=TOOL_RISKS[pattern_key],
                                file_path=file_path # Add file_path to finding
                            )
                            if not is_finding_ignored(finding, ignored_findings, base_path):
                                report.findings.append(finding)
                            processed_patterns.add((pattern_key, node.lineno))

                    # CrewAI Import Check
                    if 'crewai' in full_module_name or module_base == 'crewai':
                        pattern_key = 'crewai_import'
                        if (pattern_key, node.lineno) not in processed_patterns:
                             # Check if 'crewai_import' exists in TOOL_RISKS before accessing
                            if pattern_key in TOOL_RISKS:
                                context = ast.get_source_segment(source, node)
                                finding = SecurityFinding(
                                    pattern=pattern_key,
                                    risk_level=TOOL_RISKS[pattern_key].risk_level,
                                    line_number=node.lineno,
                                    context=context,
                                    security_info=TOOL_RISKS[pattern_key],
                                    file_path=file_path # Add file_path to finding
                                )
                                if not is_finding_ignored(finding, ignored_findings, base_path):
                                    report.findings.append(finding)
                                processed_patterns.add((pattern_key, node.lineno))
                            else:
                                # Handle case where pattern key might be missing (optional logging/warning)
                                pass # Or log a warning: print(f"Warning: Pattern key '{pattern_key}' not found in TOOL_RISKS.")


            # Check for tool usage and specific function calls
            elif isinstance(node, ast.Call):
                func_name = ""
                if hasattr(node.func, 'id'): # Direct function call like Tool()
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute) and hasattr(node.func.value, 'id'): # Method call like crewai.Agent()
                     # We might want to check node.func.attr as well if needed
                     pass # Keep func_name empty for now or refine if needed

                # General Tool Risk Check
                if func_name and func_name in TOOL_RISKS:
                    if (func_name, node.lineno) not in processed_patterns:
                        context = ast.get_source_segment(source, node)
                        finding = SecurityFinding(
                            pattern=func_name,
                            risk_level=TOOL_RISKS[func_name].risk_level,
                            line_number=node.lineno,
                            context=context,
                            security_info=TOOL_RISKS[func_name],
                            file_path=file_path # Add file_path to finding
                        )
                        if not is_finding_ignored(finding, ignored_findings, base_path):
                            report.findings.append(finding)
                        processed_patterns.add((func_name, node.lineno))

                # CrewAI Agent/Task Check
                if func_name in ['Agent', 'Task']:
                    pattern_key = f"crewai_{func_name.lower()}" # crewai_agent or crewai_task
                    if pattern_key in TOOL_RISKS and (pattern_key, node.lineno) not in processed_patterns:
                        context = ast.get_source_segment(source, node)
                        finding = SecurityFinding(
                            pattern=pattern_key,
                            risk_level=TOOL_RISKS[pattern_key].risk_level,
                            line_number=node.lineno,
                            context=context,
                            security_info=TOOL_RISKS[pattern_key],
                            file_path=file_path # Add file_path to finding
                        )
                        if not is_finding_ignored(finding, ignored_findings, base_path):
                           report.findings.append(finding)
                        processed_patterns.add((pattern_key, node.lineno))


                # Check for risky LangChain Tool definitions
                if isinstance(node.func, ast.Name) and node.func.id == 'Tool':
                    # Look for risky tool definitions
                    for kw in node.keywords:
                        if kw.arg == 'description' and isinstance(kw.value, ast.Str):
                            desc = kw.value.s
                            if any(term in desc.lower() for term in ["arbitrary", "any", "unrestricted", "full access"]):
                                finding = SecurityFinding(
                                    pattern="risky_tool_definition",
                                    risk_level=RiskLevel.HIGH,
                                    line_number=node.lineno,
                                    context=desc,
                                    security_info=YAML_TOOL_PATTERNS['risky_tool_description'],
                                    file_path=file_path # Add file_path to finding
                                )
                                if not is_finding_ignored(finding, ignored_findings, base_path):
                                    report.findings.append(finding)

                        elif kw.arg == 'func' and isinstance(kw.value, ast.Lambda):
                            # Check for risky lambda functions
                            if isinstance(kw.value.body, ast.Call) and isinstance(kw.value.body.func, ast.Name):
                                if kw.value.body.func.id in ['eval', 'exec']:
                                    finding = SecurityFinding(
                                        pattern="unsafe_code_execution",
                                        risk_level=RiskLevel.CRITICAL,
                                        line_number=node.lineno,
                                        context=ast.get_source_segment(source, kw.value),
                                        security_info=SecurityInfo(
                                            risk_level=RiskLevel.CRITICAL,
                                            description="Unsafe code execution in tool definition",
                                            impact="Arbitrary code execution vulnerability",
                                            remediation="1. Remove eval/exec usage\n2. Use safe alternatives\n3. Implement input validation",
                                            pattern=re.compile(r'eval|exec')
                                        ),
                                        file_path=file_path # Add file_path to finding
                                    )
                                    if not is_finding_ignored(finding, ignored_findings, base_path):
                                        report.findings.append(finding)

            # Check for CrewAI @tool decorator
            elif isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    is_tool_decorator = False
                    if isinstance(decorator, ast.Name) and decorator.id == 'tool': # Simple @tool
                        is_tool_decorator = True
                    elif isinstance(decorator, ast.Call) and hasattr(decorator.func, 'id') and decorator.func.id == 'tool': # @tool(...)
                        is_tool_decorator = True

                    if is_tool_decorator:
                        pattern_key = 'crewai_tool_decorator'
                        if pattern_key in TOOL_RISKS and (pattern_key, node.lineno) not in processed_patterns:
                            context = ast.get_source_segment(source, node) # Get the whole function definition
                            finding = SecurityFinding(
                                pattern=pattern_key,
                                risk_level=TOOL_RISKS[pattern_key].risk_level,
                                line_number=node.lineno, # Line number of the function definition
                                context=context,
                                security_info=TOOL_RISKS[pattern_key],
                                file_path=file_path # Add file_path to finding
                            )
                            if not is_finding_ignored(finding, ignored_findings, base_path):
                                report.findings.append(finding)
                            processed_patterns.add((pattern_key, node.lineno))
                        break # Found the @tool decorator, no need to check others for this function
 
         # Calculate overall risk based on findings (outside the loop, inside try)
        if report.findings:
            risk_levels = [f.risk_level for f in report.findings]
            report.overall_risk = max(risk_levels)

    except Exception as e: # Correctly aligned with try
        print(f"Error scanning Python file {file_path}: {e}")
        report.overall_risk = RiskLevel.CRITICAL
        report.metadata = {"error": str(e)}

    return report

def scan_yaml_content(content: str, file_path: str, ignored_findings: Set[Tuple[str, int, str]], base_path: Path) -> SecurityReport:
    """
    Scan YAML content for security patterns, skipping ignored findings.

    Args:
        content: YAML content to scan
        file_path: Path to the YAML file
        ignored_findings: Set of findings to ignore
        base_path: The base path from which the scan was initiated

    Returns:
        SecurityReport containing findings with detailed security information
    """
    report = SecurityReport(
        findings=[],
        overall_risk=RiskLevel.LOW,
        file_path=file_path,
        timestamp=datetime.now().isoformat()
    )
    
    try:
        # Check for dangerous YAML tags first
        if any(tag in content for tag in ['!!python/', '!!python/object', '!!python/name']):
            finding = SecurityFinding(
                pattern="yaml_injection",
                risk_level=RiskLevel.CRITICAL,
                line_number=0, # Use 0 or a specific line if detectable, None might cause issues with ignore check
                context="Dangerous YAML tags detected",
                security_info=SecurityInfo(
                    risk_level=RiskLevel.CRITICAL,
                    description="YAML injection attempt detected",
                    impact="Potential arbitrary code execution",
                    remediation="1. Disable custom YAML tags\n2. Use safe YAML loader\n3. Validate YAML content",
                    pattern=re.compile(r'!!python/')
                ),
                file_path=file_path # Add file_path to finding
            )
            # YAML injection is critical, don't check ignore list for this one maybe? Or check if needed.
            # if not is_finding_ignored(finding, ignored_findings, base_path):
            report.findings.append(finding)
            report.overall_risk = RiskLevel.CRITICAL
            return report # Return early for critical YAML injection
        
        # Use ruamel.yaml for better line number support
        yaml = ruamel.yaml.YAML(typ='safe')
        data = yaml.load(content)
        
        # Create a line map for faster lookups
        lines = content.split('\n')
        line_map = {}
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                for key in stripped.split(':')[0].strip().split():
                    line_map[key] = i
        
        def scan_nested(data, path="", parent_key="", line_number=None):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Get line number using line map or ruamel.yaml's line cache
                    current_line = line_number
                    if str(key) in line_map:
                        current_line = line_map[str(key)]
                    elif hasattr(key, 'lc'):
                        current_line = key.lc.line + 1
                    
                    # Check each pattern against the key and value
                    for pattern_name, security_info in YAML_TOOL_PATTERNS.items():
                        # Check key against pattern
                        if security_info.pattern.search(str(key)):
                            # Get context by finding the relevant lines
                            context_lines = []
                            if current_line:
                                # Get up to 3 lines of context
                                start = max(0, current_line - 1)
                                end = min(len(lines), current_line + 2)
                                context_lines = lines[start:end]
                            
                            finding = SecurityFinding(
                                pattern=pattern_name,
                                risk_level=security_info.risk_level,
                                line_number=current_line,
                                context='\n'.join(context_lines),
                                security_info=security_info,
                                file_path=file_path # Add file_path to finding
                            )
                            if not is_finding_ignored(finding, ignored_findings, base_path):
                                report.findings.append(finding)

                        # Check value against pattern if it's a string
                        if isinstance(value, str) and security_info.pattern.search(value):
                            context_lines = []
                            if current_line:
                                # Get up to 3 lines of context
                                start = max(0, current_line - 1)
                                end = min(len(lines), current_line + 2)
                                context_lines = lines[start:end]
                            
                            finding = SecurityFinding(
                                pattern=pattern_name,
                                risk_level=security_info.risk_level,
                                line_number=current_line,
                                context='\n'.join(context_lines),
                                security_info=security_info,
                                file_path=file_path # Add file_path to finding
                            )
                            # Avoid adding duplicate findings if key and value match the same pattern on the same line
                            is_duplicate = any(
                                f.pattern == finding.pattern and f.line_number == finding.line_number
                                for f in report.findings
                            )
                            if not is_duplicate and not is_finding_ignored(finding, ignored_findings, base_path):
                                report.findings.append(finding)

                    # Recursively scan nested structures
                    if isinstance(value, (dict, list)):
                        scan_nested(value, current_path, key, current_line)
            
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    current_path = f"{path}[{i}]"
                    scan_nested(item, current_path, parent_key, line_number)
        
        # Start scanning from the root
        scan_nested(data)
        
        # Calculate overall risk based on findings
        if report.findings:
            risk_levels = [f.risk_level for f in report.findings]
            report.overall_risk = max(risk_levels)
        
    except Exception as e:
        print(f"Error scanning YAML file {file_path}: {e}")
        report.overall_risk = RiskLevel.CRITICAL
        report.metadata = {"error": str(e)}
        
    return report

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
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if file_path.suffix == '.py':
        return scan_python_file(str(file_path), ignored_findings, base_path)
    elif file_path.suffix in ['.yaml', '.yml']:
        with open(file_path, 'r') as f:
            content = f.read()
        return scan_yaml_content(content, str(file_path), ignored_findings, base_path)
    else:
        # For unsupported file types, return an empty report
        return SecurityReport(
            findings=[],
            overall_risk=RiskLevel.LOW,
            file_path=str(file_path),
            timestamp=datetime.now().isoformat()
        )

def print_report(report: SecurityReport):
    """
    Print a formatted security report.
    
    Args:
        report: SecurityReport to print
    """
    console = Console()
    
    # Print file information
    console.print(f"\n[bold]Security Report for: {report.file_path}[/bold]")
    console.print(f"Generated: {report.timestamp}")
    console.print(f"Overall Risk Level: {report.overall_risk.name}")
    
    if not report.findings:
        console.print("[green]No security issues found![/green]")
        return
    
    # Group findings by risk level
    findings_by_risk = {}
    for finding in report.findings:
        if finding.risk_level not in findings_by_risk:
            findings_by_risk[finding.risk_level] = []
        findings_by_risk[finding.risk_level].append(finding)
    
    # Print findings by risk level
    for risk_level in sorted(findings_by_risk.keys(), reverse=True):
        console.print(f"\n[bold]{risk_level.name} Risk Findings:[/bold]")
        
        # Create table for this risk level
        table = Table(
            show_header=True,
            header_style="bold",
            border_style="red" if risk_level == RiskLevel.CRITICAL else "yellow" if risk_level == RiskLevel.HIGH else "blue",
            expand=True,
            show_lines=True
        )
        
        # Add columns
        table.add_column("Line", style="dim", no_wrap=True)
        table.add_column("Pattern", style="bold")
        table.add_column("Description", style="white")
        table.add_column("Context", style="bright_black")
        table.add_column("Impact", style="magenta")
        table.add_column("Remediation", style="green")
        
        # Add rows
        for finding in findings_by_risk[risk_level]:
            # Format context with line numbers
            context_lines = []
            if finding.context:
                for i, line in enumerate(finding.context.split('\n')):
                    line_num = finding.line_number + i if finding.line_number else "N/A"
                    context_lines.append(f"Line {line_num}: {line}")
            
            # Add row to table
            table.add_row(
                str(finding.line_number) if finding.line_number else "N/A",
                finding.pattern,
                finding.security_info.description,
                "\n".join(context_lines),
                finding.security_info.impact,
                finding.security_info.remediation
            )
        
        console.print(table)
        console.print()  # Add spacing between risk levels

def main():
    """
    Main entry point for the scanner.
    """
    import sys
    import glob
    
    if len(sys.argv) < 2:
        print("Usage: python -m agent_security.scanner <path>")
        sys.exit(1)
    
    path = sys.argv[1]
    if not Path(path).exists():
        print(f"Path not found: {path}")
        sys.exit(1)
    
    # Handle both files and directories
    if Path(path).is_file():
        report = scan_file(path)
        print_report(report)
    else:
        # Scan all Python and YAML files in the directory
        for ext in ['*.py', '*.yaml', '*.yml']:
            for file_path in glob.glob(str(Path(path) / '**' / ext), recursive=True):
                report = scan_file(file_path)
                print_report(report)

if __name__ == '__main__':
    main()

def scan_git_repository(repo_url: str, branch: Optional[str] = None) -> List[SecurityReport]:
    """
    Scan a Git repository for security issues in LLM agent configurations.

    Args:
        repo_url: URL of the Git repository
        branch: Optional branch to scan

    Returns:
        List of SecurityReport objects for each file scanned
    """
    reports = []
    try:
        with GitScanner(repo_url, branch) as git_scanner:
            reports = git_scanner.scan_repository()
    except Exception as e:
        print(f"Error scanning Git repository {repo_url}: {e}")
    return reports