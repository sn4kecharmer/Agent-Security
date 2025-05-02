"""
Command-line interface for the Agent Security Scanner.
"""

import json
import typer
import csv  # Added for CSV export
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from pathlib import Path
from typing import Optional, List, Dict, Any  # Added Dict, Any
import datetime  # Added for timestamp in report processing
import argparse
from .models import RiskLevel
from .scanner import scan_file, scan_git_repository, load_ignored_findings # Import load_ignored_findings
from .patterns import TOOL_RISKS, YAML_TOOL_PATTERNS

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
                    security_info.get("description", ""),
                    impact_detail,
                    security_info.get("remediation", ""),
                    finding.get("pattern", ""),  # Use pattern as pattern_id
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


def main(args):
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

    args = parser.parse_args()

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
                for ext in ['*.py', '*.yaml', '*.yml']:
                    # Use rglob for recursive search
                    for file_p in target_path.rglob(ext):
                         # Skip files within .git directories or other common ignores if needed
                         if ".git" in file_p.parts:
                              continue
                         print(f"Scanning file: {file_p}")
                         try:
                              file_report = scan_file(str(file_p), ignored_set, base_path)
                              if file_report and file_report.findings: # Only add reports with findings
                                   all_reports.append(file_report)
                         except FileNotFoundError:
                              console.print(f"[yellow]Warning:[/yellow] Skipping file not found during directory scan: {file_p}")
                         except Exception as e:
                              console.print(f"[red]Error scanning file {file_p}:[/red] {e}")
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

        # 1. Generate CSV if requested
        if args.output_csv:
            generate_csv_report(flat_findings_for_csv, args.output_csv)

        # 2. Generate JSON output (to file or stdout)
        output_json_str = json.dumps(final_json_output, indent=2)
        # Write to file or print to stdout
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_json_str)
        else:
            print(output_json_str)

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())