"""
Command-line interface for the Agent Security Scanner.
"""

import json
import sys
import typer
import csv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.logging import RichHandler
from pathlib import Path
from typing import Optional, List, Dict, Any
import datetime
import argparse
import re
import logging
import os
import glob
from contextlib import redirect_stdout

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None # Handle missing library later
from .models import RiskLevel, SecurityInfo, SecurityReport
from .scanner import scan_file, scan_git_repository, load_ignored_findings, GET_allowed_actions, GET_contextual_risk_for_action
from .patterns import TOOL_RISKS, YAML_TOOL_PATTERNS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True, markup=True),
        logging.FileHandler("agent_security.log", mode="w")
    ]
)

logger = logging.getLogger("agent_security")

app = typer.Typer(
    help="Agent Security Scanner - Analyze LLM agent configurations for security risks"
)
console = Console()

# Try to import git support, but make it optional
try:
    from .scanner import scan_git_repository
    HAS_GIT_SUPPORT = True
except ImportError:
    HAS_GIT_SUPPORT = False

def format_risk_level(risk: str) -> str:
    """Format risk level for display."""
    if risk == "CRITICAL":
        return "[bold red]CRITICAL[/bold red]"
    elif risk == "HIGH":
        return "[red]HIGH[/red]"
    elif risk == "MEDIUM":
        return "[yellow]MEDIUM[/yellow]"
    return "[green]LOW[/green]"


def print_risk_explanation(risk: str):
    """Print explanation of risk levels."""
    explanations = {
        "CRITICAL": """
        [bold red]CRITICAL Risk[/bold red] tools can:
        - Execute arbitrary system commands
        - Execute arbitrary code
        - Access sensitive system resources without restrictions
        - Potentially lead to system compromise
        - Require immediate attention and remediation
        """,
        "HIGH": """
        [red]HIGH Risk[/red] tools can:
        - Execute arbitrary commands
        - Read/write files
        - Make unrestricted web requests
        - Access sensitive system resources
        """,
        "MEDIUM": """
        [yellow]MEDIUM Risk[/yellow] tools can:
        - Access external APIs
        - Process user input
        - Make limited web requests
        - Access some system resources
        """,
        "LOW": """
        [green]LOW Risk[/green] tools:
        - Perform safe, isolated operations
        - Have no external access
        - Process only local data
        """
    }
    console.print(Panel(Markdown(explanations[risk]), title="Risk Level Explanation"))


@app.command()
def scan(
    target: str = typer.Argument(..., help="File, directory, or Git URL to scan"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Git branch to scan"),
    explain: bool = typer.Option(False, "--explain", help="Show detailed explanations"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results"),
    output_csv: Optional[str] = typer.Option(None, "--output-csv", help="Output CSV file for results"),
    output_html: Optional[str] = typer.Option(None, "--output-html", help="Output HTML file for results"),
    json_stdout: bool = typer.Option(False, "--json-stdout", help="Write the JSON report to stdout"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", case_sensitive=False, help="Exit with status 1 when findings meet or exceed: critical, high, medium, or low")
):
    """
    Scan agent configurations for security issues.
    """
    try:
        # Perform the scan
        if json_stdout:
            previous_disable_level = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                with redirect_stdout(sys.stderr):
                    report = scan_target(target, branch, explain)
            finally:
                logging.disable(previous_disable_level)
        else:
            report = scan_target(target, branch, explain)

        if json_stdout:
            sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
            sys.stdout.flush()
            if fail_on:
                threshold = fail_on.upper()
                risk_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                if threshold not in risk_order:
                    raise typer.BadParameter("Choose critical, high, medium, or low for --fail-on")
                if report and risk_order.get(report.overall_risk.name, 0) >= risk_order[threshold]:
                    raise typer.Exit(code=1)
            return
        
        # Convert findings to list format
        findings_list = []
        if report and hasattr(report, 'findings'):
            findings_list = [
                {
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "pattern": finding.pattern,
                    "risk_level": finding.risk_level.name if hasattr(finding.risk_level, 'name') else str(finding.risk_level),
                    "context": finding.context,
                    "security_info": finding.security_info.__dict__ if finding.security_info else {}
                }
                for finding in report.findings
            ]
        
        # Handle HTML output if requested
        if output_html:
            generate_html_report(findings_list, output_html)
        
        # Handle CSV output if requested
        if output_csv:
            generate_csv_report(findings_list, output_csv)
        
        # Handle JSON output if requested
        if output:
            try:
                abs_path = os.path.abspath(output)
                with open(abs_path, "w", encoding="utf-8") as f:
                    json_data = report.to_dict() if report else {}
                    json.dump(json_data, f, indent=2)
                    f.flush()  # Force flush the file
                console.print(f"Results exported to [green]{output}[/green]")
            except Exception as e:
                logger.error(f"Error during JSON report generation: {e}")
        
        # Display the report in the console
        display_report(report, explain)

        if fail_on:
            threshold = fail_on.upper()
            risk_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if threshold not in risk_order:
                raise typer.BadParameter("Choose critical, high, medium, or low for --fail-on")
            if report and risk_order.get(report.overall_risk.name, 0) >= risk_order[threshold]:
                raise typer.Exit(code=1)
        
    except typer.Exit:
        raise
    except Exception as e:
        logging.error(f"Error: {e}")
        if "--verbose" in sys.argv:
            logging.exception("Detailed error:")
        sys.exit(1)


@app.command()
def list_tools():
    """List all known tools and their risk levels."""
    # Python tools
    table = Table(title="Known Python Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Risk Level")

    for finding in report.findings:
        table.add_row(finding.pattern, format_risk_level(finding.risk_level.name))

    console.print(table)

    # YAML patterns
    table = Table(title="Known YAML Tool Patterns")
    table.add_column("Pattern", style="cyan")
    table.add_column("Risk Level")

    for pattern, info in YAML_TOOL_PATTERNS.items():
        table.add_row(pattern, format_risk_level(info.risk_level.name))

    console.print(table)


def generate_csv_report(findings_list: List[Dict[str, Any]], output_filepath: str):
    """Generates a CSV report from a list of finding dictionaries."""
    header = [
        "file_path",
        "line_number",
        "finding_type",
        "risk_level",
        "severity",
        "description",
        "pattern_id",
        "impact",
        "remediation",
    ]
    try:
        logger.debug(f"generate_csv_report: Attempting to open {output_filepath} for writing.")
        with open(output_filepath, "w", newline="", encoding="utf-8") as csvfile:
            logger.debug(f"generate_csv_report: Successfully opened {output_filepath}.")
            writer = csv.writer(csvfile)
            writer.writerow(header)

            if not findings_list:
                print(f"No findings detected. Empty CSV created at {output_filepath}")
                return

            for finding in findings_list:
                # Extract data safely using .get()
                security_info = finding.get("security_info", {}) or {}  # Handle None case
                impact_detail = f"{security_info.get('impact', '')} - {finding.get('context', '')}"

                row_data = [
                    finding.get("file_path", ""),
                    finding.get("line_number", ""),
                    finding.get("pattern", ""),  # Use pattern as finding_type
                    finding.get("risk_level", ""),  # Use risk_level as severity
                    security_info.get("severity", ""),  # Add severity from security_info
                    security_info.get("description", ""),
                    finding.get("pattern", ""),  # Use pattern as pattern_id
                    impact_detail,
                    security_info.get("remediation", ""),
                ]
                writer.writerow(row_data)
            logger.debug(f"generate_csv_report: Finished writing rows to {output_filepath}.")
        print(f"CSV report successfully generated at: {output_filepath}")
        logger.info(f"CSV report successfully generated at: {output_filepath}")
    except IOError as e:
        logger.error(f"generate_csv_report: IOError when writing to {output_filepath}. Reason: {e}", exc_info=True)
        print(f"Error: Could not write CSV file to {output_filepath}. Reason: {e}")
    except AttributeError as e:
        logger.error(f"generate_csv_report: AttributeError during CSV generation for {output_filepath}: {e}", exc_info=True)
        # This might occur if the structure of finding dicts is unexpected
        print(f"Error: Missing expected attribute during CSV generation: {e}")
        print("Please check the structure of the scan results.")
    except Exception as e:
        print(f"An unexpected error occurred during CSV generation: {e}")


# --- Table Formatting ---
def format_output_table(findings_list: List[Dict[str, Any]]) -> str:
    """Formats findings into a text-based table."""
    if not findings_list:
        return "No vulnerabilities found."

    if tabulate is None:
        return "Error: 'tabulate' library not found. Please install it (`pip install tabulate`) to use table format."

    headers = ["File Path", "Line", "Pattern Name", "Severity", "Description"] # Matched Text not directly available in flat list
    table_data = []
    for finding in findings_list:
        # Extract data safely using .get()
        security_info = finding.get("security_info", {}) or {}
        table_data.append([
            finding.get("file_path", "N/A"),
            finding.get("line_number", "N/A"),
            finding.get("pattern", "N/A"), # Using pattern as Pattern Name
            finding.get("risk_level", "N/A"), # Using risk_level as Severity
            security_info.get("description", "N/A")[:100] + ('...' if len(security_info.get("description", "")) > 100 else '') # Use description, truncated
        ])

    # TDD Anchor: Test table generation with various inputs.
    return tabulate(table_data, headers=headers, tablefmt="grid")
 
 
# Helper function for formatting cell data
def _format_cell_data(data: Any) -> str:
    if data is None:
        return "N/A"
    if isinstance(data, list):
        # Ensure all items are strings before joining, and filter out None items
        return ", ".join(str(item) for item in data if item is not None)
    return str(data)

# --- Enhanced Risk Description Function ---
def generate_enhanced_risk_description(
    original_risk_description: str,
    pattern_name: Optional[str],
    content_context: Optional[str], # This is 'evidence_data'
    security_info: Optional[SecurityInfo] # This is 'security_info_obj'
) -> str:
    """
    Generates an enhanced risk description if the original is "Impact unknown...".
    """
    if original_risk_description == "Impact unknown due to custom/unknown pattern. Manual review required.":
        # Pass pattern_details (security_info) to GET_allowed_actions
        allowed_actions = GET_allowed_actions(security_info, content_context, pattern_name)
        
        if allowed_actions:
            enhancements = []
            for action in allowed_actions:
                contextual_risk = GET_contextual_risk_for_action(action)
                if contextual_risk:
                    enhancements.append(f"- Action '{action}': {contextual_risk}")
            
            if enhancements:
                return f"{original_risk_description}\nPotential inferred actions and risks:\n" + "\n".join(enhancements)
    return original_risk_description
# --- End Enhanced Risk Description Function ---

def format_results_as_table(findings_list: List[Dict[str, Any]], console_instance: Console):
    """Formats findings into a rich table and prints it."""
    if not findings_list:
        console_instance.print("No vulnerabilities found.")
        return

    table = Table(
        title="Scan Results",
        show_lines=True,
        padding=(0, 1),
        expand=True
    )
    # Add all columns including evidence and remediation
    table.add_column("File", style="cyan", no_wrap=False, overflow="fold")
    table.add_column("Line", justify="right", width=5)
    table.add_column("Description", style="italic", no_wrap=False, overflow="fold")
    table.add_column("Evidence", style="yellow", no_wrap=False, overflow="fold")
    table.add_column("Remediation", style="green", no_wrap=False, overflow="fold")
    table.add_column("Risk Level", width=10)

    for finding in findings_list:
        pattern_name = finding.get("pattern")
        security_info = finding.get("security_info", {}) or {}
        
        # Get description from security_info or tool patterns
        description_text = security_info.get("description")
        if not description_text:
            tool_info = TOOL_RISKS.get(pattern_name) or YAML_TOOL_PATTERNS.get(pattern_name)
            if tool_info:
                description_text = tool_info.description
            elif pattern_name:
                description_text = f"Unknown/Custom: {pattern_name}"
            else:
                description_text = "N/A"

        # Get evidence from finding or security_info and clean it up
        evidence_text = finding.get("context", "")
        if not evidence_text:
            evidence_text = security_info.get("evidence", "")
        if not evidence_text:
            evidence_text = "N/A"
        
        # Clean up evidence text
        evidence_text = " ".join(evidence_text.split())  # Remove extra whitespace and newlines
        evidence_text = evidence_text.strip()  # Remove leading/trailing whitespace

        # Get remediation from security_info or tool patterns
        remediation_text = security_info.get("remediation", "")
        if not remediation_text:
            tool_info = TOOL_RISKS.get(pattern_name) or YAML_TOOL_PATTERNS.get(pattern_name)
            if tool_info:
                remediation_text = tool_info.remediation
            else:
                remediation_text = "Review implementation and restrict access if needed"

        file_path_str = finding.get("file_path", "N/A")
        line_number_str = str(finding.get("line_number")) if finding.get("line_number") is not None else "N/A"
        risk_level = finding.get("risk_level", "N/A")

        # Color code the risk level
        if risk_level == "CRITICAL":
            risk_level = "[bold dark_red]CRITICAL[/bold dark_red]"
        elif risk_level == "HIGH":
            risk_level = "[bold pink]HIGH[/bold pink]"
        elif risk_level == "MEDIUM":
            risk_level = "[bold orange3]MEDIUM[/bold orange3]"
        elif risk_level == "LOW":
            risk_level = "[bold yellow]LOW[/bold yellow]"

        table.add_row(
            file_path_str,
            line_number_str,
            description_text,
            evidence_text,
            remediation_text,
            risk_level
        )
    
    console_instance.print(table)

def sanitize_error(error: Exception) -> str:
    """Sanitize error messages to prevent information leakage."""
    error_str = str(error)
    
    # Remove file paths
    error_str = re.sub(r'/[^\s]+', '[PATH]', error_str)
    
    # Remove potential tokens
    error_str = re.sub(r'(api_key|secret_key|access_key|token|password):\s*[^\s]+', r'\1: [REDACTED]', error_str)
    
    return error_str

def handle_error(error: Exception, verbose: bool = False) -> None:
    """Handle errors with appropriate logging and user feedback."""
    sanitized_error = sanitize_error(error)
    
    if verbose:
        logger.error(f"Error: {sanitized_error}", exc_info=True)
    else:
        logger.error(f"Error: {sanitized_error}")
        logger.info("Run with --verbose for more details")
    
    sys.exit(1)

def is_git_url(target: str) -> bool:
    """Check if target is a Git URL."""
    if isinstance(target, str):
        return target.startswith(("http://", "https://", "git://", "ssh://"))
    return False

def display_report(report, explain: bool = False):
    """Display the scan report."""
    if not report or not report.findings:
        console.print("No vulnerabilities found.")
        return

    table = Table(
        title="Scan Results",
        show_lines=True,  # Show horizontal lines between rows
        show_edge=True,   # Show outer edges
        padding=(0, 1)    # Add some padding for better readability
    )
    table.add_column("File")
    table.add_column("Line")
    table.add_column("Description")
    table.add_column("Evidence")
    table.add_column("Remediation")
    table.add_column("Risk Level")

    for finding in report.findings:
        # Get description and remediation from security_info
        description = finding.security_info.description if finding.security_info else "N/A"
        remediation = finding.security_info.remediation if finding.security_info else "N/A"
        
        # Use context as evidence
        evidence = finding.context if finding.context else "N/A"
        
        table.add_row(
            str(finding.file_path),
            str(finding.line_number),
            description,
            evidence,
            remediation,
            finding.risk_level.name
        )

    console.print(table)

def scan_target(target_path: str, branch: Optional[str] = None, explain: bool = False):
    """Scan a target path or Git URL."""
    if is_git_url(target_path):
        try:
            report = scan_git_repository(target_path, branch)
            return report
        except ImportError:
            console.print("[red]Error: Git support is not available. Please install git to scan repositories.[/red]")
            sys.exit(1)

    # Handle local files/directories
    path = Path(target_path)
    logger.info(f"Initial path: {path}")
    
    # Determine if we're running in Docker by checking for /scan directory
    in_docker = Path('/scan').exists()
    
    # Set base path and handle path resolution based on environment
    if in_docker:
        base_path = Path('/scan')
        # Handle various path formats in Docker
        if str(path).startswith('/scan/'):
            # Strip /scan/ prefix if present
            path = Path(str(path).replace('/scan/', '', 1))
        elif str(path).startswith('./examples/') or str(path).startswith('examples/'):
            # Strip ./ prefix if present
            path = Path(str(path).replace('./', '', 1))
        full_path = base_path / path
    else:
        # Outside Docker, use absolute paths
        path = path.resolve()
        base_path = path.parent if path.is_file() else path
        full_path = path
    
    logger.info(f"Running in Docker: {in_docker}")
    logger.info(f"Base path: {base_path}, Relative path: {path}")
    logger.info(f"Checking paths - Direct: {path} (exists: {path.exists()}), Full: {full_path} (exists: {full_path.exists()})")
    
    if not path.exists() and not full_path.exists():
        console.print(f"[red]Error: Target path '{target_path}' is not a valid file, directory, or Git URL.[/red]")
        # Print debug info about the file system
        try:
            if os.environ.get('AGENT_SECURITY_DEBUG'):
                if base_path.exists():
                    logger.info(f"Base directory {base_path} exists")
                    # List contents recursively
                    def list_dir(dir_path: Path, depth=0):
                        if depth > 3:  # Limit recursion depth
                            return
                        for item in dir_path.iterdir():
                            logger.info(f"{'  ' * depth}Found: {item}")
                            if item.is_dir() and not item.name.startswith('.'):
                                list_dir(item, depth + 1)
                    list_dir(base_path)
                else:
                    logger.info(f"Base directory {base_path} does not exist")
        except Exception as e:
            logger.error(f"Error during debug: {e}")
        sys.exit(1)

    # Use the full path if it exists, otherwise use the direct path
    scan_path = full_path if full_path.exists() else path
    logger.info(f"Using path for scan: {scan_path}")

    # Load ignored findings from the base path
    ignored_findings = load_ignored_findings(base_path)

    # Check if it's a directory or a file
    if scan_path.is_dir():
        # This is a directory scan - use glob to find all Python and YAML files
        print(f"Scanning directory: {scan_path}")
        # Create a combined report for directory scanning
        combined_report = SecurityReport(
            findings=[],
            overall_risk=RiskLevel.LOW,
            file_path=str(scan_path),
            timestamp=datetime.datetime.now().isoformat()
        )
        
        # Scan Python, YAML, and JSON agent/MCP configuration files.
        for ext in ['*.py', '*.yaml', '*.yml', '*.json']:
            for file_path in glob.glob(str(scan_path / '**' / ext), recursive=True):
                try:
                    print(f"Scanning file: {file_path}")
                    file_report = scan_file(file_path, ignored_findings, scan_path)
                    if file_report and hasattr(file_report, 'findings') and file_report.findings:
                        print(f"Found {len(file_report.findings)} issues in {file_path}")
                        combined_report.findings.extend(file_report.findings)
                        if hasattr(file_report, 'overall_risk') and file_report.overall_risk > combined_report.overall_risk:
                            combined_report.overall_risk = file_report.overall_risk
                except Exception as e:
                    print(f"Error scanning file {file_path}: {e}")
        
        return combined_report
    else:
        # Single file scan
        return scan_file(str(scan_path), ignored_findings, base_path)

@app.callback()
def callback():
    """
    Agent Security Scanner - Scan agent configurations for security issues.
    """
    pass

def generate_html_report(findings_list: List[Dict[str, Any]], output_filepath: str):
    """Generates an HTML report from a list of finding dictionaries."""
    try:
        # HTML template with inline styles
        html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Security Scan Report</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f5f5f5;">
    <div style="max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <h1 style="color: #2c3e50; margin-bottom: 20px;">Agent Security Scan Report</h1>
        <div style="margin-bottom: 30px; padding: 15px; background: #f8f9fa; border-radius: 4px;">
            <h2>Summary</h2>
            <p>Generated: {timestamp}</p>
            <p>Total Findings: {total_findings}</p>
        </div>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <thead>
                <tr>
                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">File</th>
                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Line</th>
                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Pattern</th>
                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Risk Level</th>
                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Description</th>
                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Evidence</th>
                    <th style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; background-color: #f8f9fa; font-weight: bold;">Remediation</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>
</body>
</html>'''

        if not findings_list:
            table_rows = '<tr><td colspan="7" style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd;">No findings detected.</td></tr>'
        else:
            rows = []
            for finding in findings_list:
                security_info = finding.get("security_info", {}) or {}
                risk_level = finding.get("risk_level", "")
                risk_color = {
                    "CRITICAL": "#dc3545",
                    "HIGH": "#fd7e14",
                    "MEDIUM": "#ffc107",
                    "LOW": "#28a745"
                }.get(risk_level, "#000000")
                
                evidence = finding.get("context", "")
                if not evidence:
                    evidence = security_info.get("evidence", "N/A")
                
                # Get the full file path and extract just the directory name and filename
                full_path = finding.get("file_path", "N/A")
                # Handle the case of N/A
                if full_path != "N/A":
                    import os
                    path_parts = os.path.normpath(full_path).split(os.sep)
                    if len(path_parts) > 1:
                        # Get the directory name and filename
                        directory = path_parts[-2]
                        filename = path_parts[-1]
                        file_path = f"{directory}/{filename}"
                    else:
                        # Just the filename if there's no directory
                        file_path = path_parts[-1]
                else:
                    file_path = "N/A"
                
                # Escape HTML special characters
                file_path = file_path.replace("<", "&lt;").replace(">", "&gt;")
                pattern = finding.get("pattern", "N/A").replace("<", "&lt;").replace(">", "&gt;")
                description = security_info.get("description", "N/A").replace("<", "&lt;").replace(">", "&gt;")
                evidence = evidence.replace("<", "&lt;").replace(">", "&gt;")
                remediation = security_info.get("remediation", "N/A").replace("<", "&lt;").replace(">", "&gt;")
                
                row = f'''<tr style="background-color: #ffffff;">
                    <td style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd;">{file_path}</td>
                    <td style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd;">{finding.get("line_number", "N/A")}</td>
                    <td style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd;">{pattern}</td>
                    <td style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd; color: {risk_color}; font-weight: bold;">{risk_level}</td>
                    <td style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd;">{description}</td>
                    <td style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd;"><div style="font-family: monospace; background: #f8f9fa; padding: 8px; border-radius: 4px; white-space: pre-wrap;">{evidence}</div></td>
                    <td style="padding: 12px; text-align: left; border-bottom: 1px solid #ddd;">{remediation}</td>
                </tr>'''
                rows.append(row)
            table_rows = "\n".join(rows)

        # Generate the final HTML with the current timestamp
        html_content = html_template.format(
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=len(findings_list),
            table_rows=table_rows
        )

        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"HTML report successfully generated at: {output_filepath}")
    except IOError as e:
        print(f"Error: Could not write HTML file to {output_filepath}. Reason: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during HTML generation: {e}")
        import traceback
        print(traceback.format_exc())

# Update the main function to handle HTML output
@app.command()
def main(
    file_or_dir: str = typer.Argument(..., help="File or directory to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path for JSON report"),
    output_csv: Optional[str] = typer.Option(None, "--csv", help="Output file path for CSV report"),
    output_html: Optional[str] = typer.Option(None, "--html", help="Output file path for HTML report"),
    json_stdout: bool = typer.Option(False, "--json", help="Output JSON to stdout"),
    ignore_patterns: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated list of patterns to ignore"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    args = parse_args()
    try:
        # Convert ignore patterns to a set
        ignore_set = set(ignore_patterns.split(",")) if ignore_patterns else set()
        
        # Determine if the input is a file or directory
        path = Path(file_or_dir)
        if not path.exists():
            console.print(f"[red]Error:[/red] {file_or_dir} does not exist")
            sys.exit(1)
            
        # Scan the file or directory
        if path.is_file():
            report = scan_file(file_or_dir, ignore_set, path)
        else:
            report = scan_git_repository(file_or_dir, ignore_set)
            
        # Handle JSON stdout output first
        if json_stdout:
            # Convert report to dictionary format
            report_dict = {
                "scan_summary": {
                    "total_files": report.total_files,
                    "total_findings": report.total_findings,
                    "risk_levels": {
                        "critical": report.risk_levels.get("critical", 0),
                        "high": report.risk_levels.get("high", 0),
                        "medium": report.risk_levels.get("medium", 0),
                        "low": report.risk_levels.get("low", 0),
                    }
                },
                "findings": [
                    {
                        "file": finding.file,
                        "line_number": finding.line_number,
                        "pattern": finding.pattern,
                        "risk_level": finding.risk_level,
                        "description": finding.description,
                        "recommendation": finding.recommendation,
                        "code_snippet": finding.code_snippet
                    }
                    for finding in report.findings
                ]
            }
            # Write JSON to stdout
            json.dump(report_dict, sys.stdout, indent=2)
            sys.stdout.write("\n")
            sys.stdout.flush()
            return
            
        # Handle file outputs
        if output:
            try:
                with open(output, "w", encoding="utf-8") as f:
                    # Convert report to dictionary format
                    report_dict = {
                        "scan_summary": {
                            "total_files": report.total_files,
                            "total_findings": report.total_findings,
                            "risk_levels": {
                                "critical": report.risk_levels.get("critical", 0),
                                "high": report.risk_levels.get("high", 0),
                                "medium": report.risk_levels.get("medium", 0),
                                "low": report.risk_levels.get("low", 0),
                            }
                        },
                        "findings": [
                            {
                                "file": finding.file,
                                "line_number": finding.line_number,
                                "pattern": finding.pattern,
                                "risk_level": finding.risk_level,
                                "description": finding.description,
                                "recommendation": finding.recommendation,
                                "code_snippet": finding.code_snippet
                            }
                            for finding in report.findings
                        ]
                    }
                    json.dump(report_dict, f, indent=2)
                console.print(f"Results exported to [green]{output}[/green]")
            except IOError as e:
                console.print(f"[red]Error writing JSON report:[/red] {e}")
                sys.exit(1)
                
        if output_csv:
            try:
                generate_csv_report(report.findings, output_csv)
                console.print(f"CSV report exported to [green]{output_csv}[/green]")
            except IOError as e:
                console.print(f"[red]Error writing CSV report:[/red] {e}")
                sys.exit(1)
                
        if output_html:
            try:
                generate_html_report(report, output_html)
                console.print(f"HTML report exported to [green]{output_html}[/green]")
            except IOError as e:
                console.print(f"[red]Error writing HTML report:[/red] {e}")
                sys.exit(1)
                
        # Display the report in the console if not outputting JSON to stdout
        if not json_stdout:
            display_report(report, verbose)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)

def entrypoint() -> None:
    """Run the Typer command-line application."""
    app()


if __name__ == "__main__":
    entrypoint()
