"""
Command-line interface for the Agent Security Scanner.
"""

import json
import sys # Added for sys.stdout
import typer
import csv  # Added for CSV export
from rich.console import Console
from rich.table import Table # rich.table is used by typer scan and new table func
from rich.panel import Panel
from rich.markdown import Markdown
from rich.logging import RichHandler  # Added missing import
from pathlib import Path
from typing import Optional, List, Dict, Any  # Added Dict, Any
import datetime  # Added for timestamp in report processing
import argparse
import re
import logging
import os
try:
    from tabulate import tabulate
except ImportError:
    tabulate = None # Handle missing library later
from .models import RiskLevel, SecurityInfo
from .scanner import scan_file, scan_git_repository, load_ignored_findings, GET_allowed_actions, GET_contextual_risk_for_action # Import load_ignored_findings
from .patterns import TOOL_RISKS, YAML_TOOL_PATTERNS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True, markup=True),
        logging.FileHandler("agent_security.log")
    ]
)

logger = logging.getLogger("agent_security")

app = typer.Typer(
    help="Agent Security Scanner - Analyze LLM agent configurations for security risks"
)
console = Console()


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
    file_path: Path = typer.Argument(..., help="Path to the configuration file to scan"),
    output_json: bool = typer.Option(False, "--json", help="Output results in JSON format"),
    explain: bool = typer.Option(False, "--explain", help="Show detailed explanation of risk levels"),
    fail_on_high: bool = typer.Option(False, "--fail-on-high", help="Exit with error code if high risk is detected"),
):
    """
    Scan a configuration file for LLM agent tool usage and security risks.
    """
    try:
        # Determine base path and load ignored findings for the typer command
        target_path = Path(file_path)
        if target_path.is_dir():
             # TODO: Handle directory scanning in typer command if needed
             console.print("[yellow]Warning:[/yellow] Directory scanning via the 'scan' command is not fully implemented for ignore files yet.")
             base_path = target_path
        elif target_path.is_file():
            base_path = target_path.parent
        else:
             console.print(f"[red]Error:[/red] Invalid file path: {file_path}")
             raise typer.Exit(1)

        ignored_set = load_ignored_findings(base_path)
        report = scan_file(str(file_path), ignored_set, base_path) # Pass ignored_set and base_path

        if output_json:
            console.print(json.dumps(report.to_dict(), indent=2))
            if fail_on_high and report.overall_risk == "HIGH":
                raise typer.Exit(1)
            return

        # Create a rich table for the report
        table = Table(
            title="Agent Security Report",
            show_lines=True,
            padding=(0, 1),
            expand=True
        )
        table.add_column("Title", style="cyan", no_wrap=False)
        table.add_column("Description", style="italic", no_wrap=False)
        table.add_column("Impact", style="red", no_wrap=False)
        table.add_column("Pattern", style="dim", no_wrap=False)
        table.add_column("Risk", width=8)
        table.add_column("Line", justify="right", width=5)
        table.add_column("Remediation", style="green", no_wrap=False)

        # Sort findings by risk level in decreasing order of severity
        sorted_findings = sorted(
            report.findings,
            key=lambda x: (
                {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x.risk_level.name, 0)
            ),
            reverse=True
        )

        for finding in sorted_findings:
            # Get security info for the pattern
            security_info = TOOL_RISKS.get(finding.pattern, None)
            if security_info:
                title = finding.pattern
                description = security_info.description
                impact = security_info.impact
                remediation = security_info.remediation
            else:
                title = finding.pattern
                description = "Custom or unknown pattern"
                impact = "Unknown impact - review implementation"
                remediation = "Review implementation and restrict access if needed"

            table.add_row(
                title,
                description,
                impact,
                finding.pattern,
                format_risk_level(finding.risk_level.name),
                str(finding.line_number) if finding.line_number else "N/A",
                remediation
            )

        console.print(table)
        console.print(f"\nOverall Risk Level: {format_risk_level(report.overall_risk.name)}")

        if explain:
            print_risk_explanation(report.overall_risk.name)

        if fail_on_high and report.overall_risk == "HIGH":
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise typer.Exit(1)


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
        with open(output_filepath, "w", newline="", encoding="utf-8") as csvfile:
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
        print(f"CSV report successfully generated at: {output_filepath}")
    except IOError as e:
        print(f"Error: Could not write CSV file to {output_filepath}. Reason: {e}")
    except AttributeError as e:
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
        evidence_text = finding.get("evidence", "")
        if not evidence_text:
            evidence_text = security_info.get("evidence", "")
        if not evidence_text:
            evidence_text = finding.get("context", "")
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

def main(args=None): # Allow args to be passed for testing, default to None for CLI use
    # console is defined globally
    parser = argparse.ArgumentParser(description="Scan agent configurations for security issues.")
    parser.add_argument(
        "target",
        help="File path or Git repository URL to scan"
    )
    parser.add_argument(
        "--branch",
        help="Git branch to scan (only used with repository URLs)",
        default=None
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Include detailed explanations in the output"
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: print to stdout)",
        default=None
    )
    parser.add_argument(
        "--output-csv",
        help="Output results to a CSV file at the specified path",
        default=None
    )
    parser.add_argument(
        "--export-json",
        nargs='?',
        const='scan_results.json', # Default filename if no arg provided
        default=None,
        metavar='FILEPATH',
        help="Export scan results to a JSON file. Defaults to 'scan_results.json' if no path is specified."
    )
    parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="Print scan results as JSON to standard output."
    )
    # The old --format argument is largely superseded by the new flags.
    # Keeping it for now but its behavior will be overridden if new flags are used.
    parser.add_argument(
        "-f", "--format",
        choices=['json', 'table'],
        default='table', # Defaulting to table as per new requirements if no other flags specified
        help="Output format (default: table, if not using --json-stdout or --export-json)."
    )
    # TDD Anchor: Add tests for argument parsing, including format.
 
    if isinstance(args, argparse.Namespace):
        args = list(vars(args).values())
    args = parser.parse_args(args) # Pass args for testing

    try:
        all_reports = []
        # Check if target is a Git repository URL
        if args.target.startswith(("http://", "https://", "git://")):
            # TODO: Update scan_git_repository and GitScanner to handle ignore files
            console.print("[yellow]Warning:[/yellow] Git repository scanning currently does not support .agent_security_ignore files.")
            all_reports = scan_git_repository(args.target, args.branch)
        else:
            # Treat as local path (file or directory)
            target_path = Path(args.target)
            if target_path.is_file():
                base_path = target_path.parent
                ignored_set = load_ignored_findings(base_path)
                report = scan_file(str(target_path), ignored_set, base_path)
                if report:
                    all_reports.append(report)
            elif target_path.is_dir():
                base_path = target_path
                ignored_set = load_ignored_findings(base_path)
                console.print(f"Scanning directory: {target_path}")
                # Scan all Python and YAML files in the directory
                found_files = False
                for ext in ['*.py', '*.yaml', '*.yml']:
                    # Use rglob for recursive search
                    for file_p in target_path.rglob(ext):
                         # Skip files within .git directories or other common ignores if needed
                         if ".git" in file_p.parts:
                              continue
                         found_files = True
                         print(f"Scanning file: {file_p}")
                         try:
                              file_report = scan_file(str(file_p), ignored_set, base_path)
                              if file_report and file_report.findings: # Only add reports with findings
                                   all_reports.append(file_report)
                         except FileNotFoundError:
                              console.print(f"[yellow]Warning:[/yellow] Skipping file not found during directory scan: {file_p}")
                         except Exception as e:
                              console.print(f"[red]Error scanning file {file_p}:[/red] {e}")
                
                if not found_files:
                    console.print("No vulnerabilities found.")
                elif not all_reports:
                    console.print("No vulnerabilities found in scanned files.")
            else:
                 console.print(f"[red]Error:[/red] Target path '{args.target}' is not a valid file, directory, or Git URL.")
                 raise typer.Exit(1)


        # Prepare results for JSON output and CSV export
        processed_results_for_json = []
        flat_findings_for_csv = []

        for report in all_reports:
            report_dict = report.to_dict()
            processed_results_for_json.append(report_dict)
            # Add file_path to each finding for the flat CSV list
            for finding_dict in report_dict.get('findings', []):
                finding_dict['file_path'] = report_dict.get('file_path', 'N/A')
                flat_findings_for_csv.append(finding_dict)

        # Handle single file scan case for JSON output consistency
        final_json_output = processed_results_for_json
        if not args.target.startswith(("http://", "https://", "git://")) and len(processed_results_for_json) == 1:
            final_json_output = processed_results_for_json[0]

        # --- Output Generation ---
 
        # 1. Generate CSV if requested (independent of other formats)
        if args.output_csv:
            generate_csv_report(flat_findings_for_csv, args.output_csv)
            # CSV generation prints its own confirmation or error
 
        # 2. Handle primary output: JSON stdout, JSON file, or Table stdout
        if args.json_stdout:
            # Print full scan results as JSON to sys.stdout
            sys.stdout.write(json.dumps(final_json_output, indent=2) + '\n')
        elif args.export_json:
            # Get the target filepath (either provided or default)
            filepath = args.export_json # This holds the value from const or user input
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(json.dumps(final_json_output, indent=2))
                console.print(f"Results exported to [green]{filepath}[/green]")
            except IOError as e:
                console.print(f"[red]Error:[/red] Could not write JSON report to {filepath}. Reason: {e}")
        else:
            # Default behavior: Format and print results as a table to sys.stdout
            # This also covers args.format == 'table' if no other JSON flags are set.
            format_results_as_table(flat_findings_for_csv, console)
            # The old args.output for table format to file is not explicitly supported by new reqs.
            # The old args.format == 'json' without other flags would also fall here,
            # printing table. This is a change from previous behavior if only --format=json was used.
            # However, the new flags --json-stdout and --export-json are more specific.
            if args.output and args.format == 'json' and not args.json_stdout and not args.export_json:
                 # This case is a bit ambiguous now. The old --output with --format=json
                 # would write JSON to a file. The new flags handle JSON export explicitly.
                 # For now, if --output is given and --format=json, but no new JSON flags,
                 # we can honor the old behavior for --output.
                 try:
                     with open(args.output, "w", encoding="utf-8") as f:
                         f.write(json.dumps(final_json_output, indent=2))
                     console.print(f"JSON report (via --output) successfully generated at: [green]{args.output}[/green]")
                 except IOError as e:
                     console.print(f"[red]Error:[/red] Could not write JSON report (via --output) to {args.output}. Reason: {e}")
            elif args.output and args.format == 'table' and not args.json_stdout and not args.export_json:
                # If user explicitly asked for table output to a file via old --output and --format=table
                # we can try to support it, though rich table to file is less ideal than direct print.
                # The format_output_table (tabulate) could be used here if preferred for file output.
                # For simplicity, current table output is via rich to console.
                # This path is less likely given the new flags.
                console.print(f"[yellow]Warning:[/yellow] Outputting table to file via --output is not the primary supported method. Table is printed to console.")


    except Exception as e:
        handle_error(e, args.explain)


if __name__ == "__main__":
    # Pass sys.argv[1:] to main if running as script, otherwise use default None
    import sys
    exit(main(sys.argv[1:]))