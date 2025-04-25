"""
Command-line interface for the Agent Security Scanner.
"""

import json
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from pathlib import Path
from typing import Optional, List
import argparse
from .models import RiskLevel
from .scanner import scan_file, scan_git_repository
from .patterns import TOOL_RISKS, YAML_TOOL_PATTERNS

app = typer.Typer(help="Agent Security Scanner - Analyze LLM agent configurations for security risks")
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
    fail_on_high: bool = typer.Option(False, "--fail-on-high", help="Exit with error code if high risk is detected")
):
    """
    Scan a configuration file for LLM agent tool usage and security risks.
    """
    try:
        report = scan_file(str(file_path))
        
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

def main():
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
    
    args = parser.parse_args()
    
    try:
        # Check if target is a Git repository URL
        if args.target.startswith(("http://", "https://", "git://")):
            results = scan_git_repository(args.target, args.branch)
        else:
            # Treat as file path
            results = scan_file(args.target).to_dict()
        
        # Format output
        output = json.dumps(results, indent=2)
        
        # Write to file or print to stdout
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
        else:
            print(output)
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 