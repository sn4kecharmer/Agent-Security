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
from .patterns import TOOL_RISKS, YAML_TOOL_PATTERNS, ACTION_RISK_DESCRIPTIONS
import ruamel.yaml
from datetime import datetime
from tabulate import tabulate
import textwrap
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import os

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
                            print(f"Warning: Skipping invalid ignore entry: {line}")
                    else:
                        print(f"Warning: Skipping malformed ignore entry: {line}")
        except IOError as e:
            print(f"Warning: Could not read ignore file {ignore_file_path}: {e}")
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
                                file_path=file_path
                            )
                            if not is_finding_ignored(finding, ignored_findings, base_path):
                                report.findings.append(finding)
                            processed_patterns.add((pattern_key, node.lineno))

                    # CrewAI Import Check
                    if 'crewai' in full_module_name or module_base == 'crewai':
                        pattern_key = 'crewai_import'
                        if (pattern_key, node.lineno) not in processed_patterns:
                            if pattern_key in TOOL_RISKS:
                                context = ast.get_source_segment(source, node)
                                finding = SecurityFinding(
                                    pattern=pattern_key,
                                    risk_level=TOOL_RISKS[pattern_key].risk_level,
                                    line_number=node.lineno,
                                    context=context,
                                    security_info=TOOL_RISKS[pattern_key],
                                    file_path=file_path
                                )
                                if not is_finding_ignored(finding, ignored_findings, base_path):
                                    report.findings.append(finding)
                                processed_patterns.add((pattern_key, node.lineno))

                    # CrewAI Memory Import Check
                    if 'crewai.memory' in full_module_name or (module_base == 'crewai' and 'memory' in module_name):
                        pattern_key = 'crewai_memory'
                        if (pattern_key, node.lineno) not in processed_patterns:
                            if pattern_key in TOOL_RISKS:
                                context = ast.get_source_segment(source, node)
                                finding = SecurityFinding(
                                    pattern=pattern_key,
                                    risk_level=TOOL_RISKS[pattern_key].risk_level,
                                    line_number=node.lineno,
                                    context=context,
                                    security_info=TOOL_RISKS[pattern_key],
                                    file_path=file_path
                                )
                                if not is_finding_ignored(finding, ignored_findings, base_path):
                                    report.findings.append(finding)
                                processed_patterns.add((pattern_key, node.lineno))

            # Check for memory usage in function calls and assignments
            elif isinstance(node, (ast.Call, ast.Assign)):
                # Check for memory usage in function calls
                if isinstance(node, ast.Call):
                    if hasattr(node.func, 'id') and node.func.id == 'Memory':
                        pattern_key = 'crewai_memory'
                        if (pattern_key, node.lineno) not in processed_patterns:
                            context = ast.get_source_segment(source, node)
                            finding = SecurityFinding(
                                pattern=pattern_key,
                                risk_level=TOOL_RISKS[pattern_key].risk_level,
                                line_number=node.lineno,
                                context=context,
                                security_info=TOOL_RISKS[pattern_key],
                                file_path=file_path
                            )
                            if not is_finding_ignored(finding, ignored_findings, base_path):
                                report.findings.append(finding)
                            processed_patterns.add((pattern_key, node.lineno))

                # Check for memory usage in assignments
                elif isinstance(node, ast.Assign):
                    for keyword in ['memory', 'Memory']:
                        if any(isinstance(target, ast.Name) and target.id == keyword for target in node.targets):
                            pattern_key = 'crewai_memory'
                            if (pattern_key, node.lineno) not in processed_patterns:
                                context = ast.get_source_segment(source, node)
                                finding = SecurityFinding(
                                    pattern=pattern_key,
                                    risk_level=TOOL_RISKS[pattern_key].risk_level,
                                    line_number=node.lineno,
                                    context=context,
                                    security_info=TOOL_RISKS[pattern_key],
                                    file_path=file_path
                                )
                                if not is_finding_ignored(finding, ignored_findings, base_path):
                                    report.findings.append(finding)
                                processed_patterns.add((pattern_key, node.lineno))

            # Check for memory usage in keyword arguments
            elif isinstance(node, ast.keyword) and node.arg == 'memory':
                pattern_key = 'crewai_memory'
                if (pattern_key, node.lineno) not in processed_patterns:
                    context = ast.get_source_segment(source, node)
                    finding = SecurityFinding(
                        pattern=pattern_key,
                        risk_level=TOOL_RISKS[pattern_key].risk_level,
                        line_number=node.lineno,
                        context=context,
                        security_info=TOOL_RISKS[pattern_key],
                        file_path=file_path
                    )
                    if not is_finding_ignored(finding, ignored_findings, base_path):
                        report.findings.append(finding)
                    processed_patterns.add((pattern_key, node.lineno))

            # Check for tool usage and specific function calls
            elif isinstance(node, ast.Call):
                func_name = ""
                if hasattr(node.func, 'id'): # Direct function call like Tool()
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute): # Method call like crew.kickoff()
                    # Check for CrewAI autonomous execution methods
                    if node.func.attr in ['kickoff', 'process', 'run']:
                        pattern_key = 'crewai_autonomous'
                        if pattern_key in TOOL_RISKS and (pattern_key, node.lineno) not in processed_patterns:
                            context = ast.get_source_segment(source, node)
                            finding = SecurityFinding(
                                pattern=pattern_key,
                                risk_level=TOOL_RISKS[pattern_key].risk_level,
                                line_number=node.lineno,
                                context=context,
                                security_info=TOOL_RISKS[pattern_key],
                                file_path=file_path
                            )
                            if not is_finding_ignored(finding, ignored_findings, base_path):
                                report.findings.append(finding)
                            processed_patterns.add((pattern_key, node.lineno))
                    # Keep func_name empty for general method calls unless specifically handled

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
                if func_name in ['Agent', 'Task', 'Crew']:
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
        
    # Validate that file_path is within base_path
    try:
        file_path = file_path.resolve(strict=True)
        base_path = base_path.resolve(strict=True)
        if not str(file_path).startswith(str(base_path)):
            raise ValueError(f"File {file_path} is outside the base directory {base_path}")
    except Exception as e:
        raise ValueError(f"Path validation failed: {e}")

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