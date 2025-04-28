"""
Main entry point for the Agent Security Scanner.
"""
import sys, argparse
from .cli import main

def entry_point():
    parser = argparse.ArgumentParser(description="Agent Security Scanner")
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
    sys.exit(main(args))

if __name__ == "__main__":
    entry_point()