import unittest
import argparse
from unittest import mock
import json
import sys
from pathlib import Path
import re
import datetime

# Assuming cli.py is in the parent directory relative to the tests directory
# For direct execution or if agent_security is installed, this might need adjustment.
# For testing within a package structure, relative imports are preferred.
from agent_security import cli 
from agent_security.models import SecurityReport, SecurityFinding, RiskLevel, SecurityInfo

# A console object mock to be used in tests
console_mock = mock.MagicMock()

# Fixed timestamp for all tests
FIXED_TIMESTAMP = "2025-05-08T22:30:33.690348"

# Sample scan results to be used in multiple tests
SAMPLE_FINDING_1 = SecurityFinding(
    pattern="os.system",
    line_number=10,
    risk_level=RiskLevel.CRITICAL,
    context="os.system('rm -rf /')",
    security_info=SecurityInfo(
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile("os.system"),
        description="Allows arbitrary command execution.",
        impact="System compromise.",
        remediation="Avoid os.system."
    )
)
SAMPLE_FINDING_2 = SecurityFinding(
    pattern="requests.get",
    line_number=25,
    risk_level=RiskLevel.MEDIUM,
    context="requests.get(user_url)",
    security_info=SecurityInfo(
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile("requests.get"),
        description="Makes HTTP GET requests.",
        impact="Data exfiltration or SSRF if URL is user-controlled.",
        remediation="Validate URLs."
    )
)
SAMPLE_REPORT_SINGLE_FILE = SecurityReport(
    file_path="test_file.py",
    findings=[SAMPLE_FINDING_1, SAMPLE_FINDING_2],
    overall_risk=RiskLevel.CRITICAL,
    timestamp=FIXED_TIMESTAMP
)
SAMPLE_REPORT_EMPTY = SecurityReport(
    file_path="empty_file.py",
    findings=[],
    overall_risk=RiskLevel.LOW,
    timestamp=FIXED_TIMESTAMP
)

# Convert sample reports to the dictionary format expected by some parts of cli.py
PROCESSED_SAMPLE_RESULTS_SINGLE = [SAMPLE_REPORT_SINGLE_FILE.to_dict()]
FLAT_SAMPLE_FINDINGS_SINGLE = [
    {
        "pattern": "os.system",
        "risk_level": "CRITICAL",
        "line_number": 10,
        "context": "os.system('rm -rf /')",
        "security_info": {
            "description": "Allows arbitrary command execution.",
            "impact": "System compromise.",
            "remediation": "Avoid os.system.",
            "severity": "🔴",
            "confidence": "High",
            "category": "",
            "cwe": [],
            "owasp": []
        },
        "file_path": "test_file.py"
    },
    {
        "pattern": "requests.get",
        "risk_level": "MEDIUM",
        "line_number": 25,
        "context": "requests.get(user_url)",
        "security_info": {
            "description": "Makes HTTP GET requests.",
            "impact": "Data exfiltration or SSRF if URL is user-controlled.",
            "remediation": "Validate URLs.",
            "severity": "🟡",
            "confidence": "High",
            "category": "",
            "cwe": [],
            "owasp": []
        },
        "file_path": "test_file.py"
    }
]
JSON_OUTPUT_SINGLE_FILE_SCAN = {
    "findings": [
        {
            "pattern": "os.system",
            "risk_level": "CRITICAL",
            "line_number": 10,
            "context": "os.system('rm -rf /')",
            "security_info": {
                "description": "Allows arbitrary command execution.",
                "impact": "System compromise.",
                "remediation": "Avoid os.system.",
                "severity": "🔴",
                "confidence": "High",
                "category": "",
                "cwe": [],
                "owasp": []
            },
            "file_path": "test_file.py"
        },
        {
            "pattern": "requests.get",
            "risk_level": "MEDIUM",
            "line_number": 25,
            "context": "requests.get(user_url)",
            "security_info": {
                "description": "Makes HTTP GET requests.",
                "impact": "Data exfiltration or SSRF if URL is user-controlled.",
                "remediation": "Validate URLs.",
                "severity": "🟡",
                "confidence": "High",
                "category": "",
                "cwe": [],
                "owasp": []
            },
            "file_path": "test_file.py"
        }
    ],
    "overall_risk": "CRITICAL",
    "file_path": "test_file.py",
    "timestamp": FIXED_TIMESTAMP,
    "metadata": {}
}

PROCESSED_SAMPLE_RESULTS_EMPTY = [SAMPLE_REPORT_EMPTY.to_dict()]
FLAT_SAMPLE_FINDINGS_EMPTY = []
JSON_OUTPUT_EMPTY_FILE_SCAN = {
    "findings": [],
    "overall_risk": "LOW",
    "file_path": "empty_file.py",
    "timestamp": FIXED_TIMESTAMP,
    "metadata": {}
}


class TestCliArgParsing(unittest.TestCase):
    """Tests for argument parsing in cli.py's main function."""

    def setUp(self):
        # Mock datetime to return fixed timestamp
        self.datetime_patcher = mock.patch('datetime.datetime')
        self.mock_datetime = self.datetime_patcher.start()
        self.mock_datetime.now.return_value.isoformat.return_value = FIXED_TIMESTAMP

        # This parser is similar to the one in cli.main()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument(
            "target",
            help="File path or Git repository URL to scan"
        )
        self.parser.add_argument(
            "--branch",
            help="Git branch to scan",
            default=None
        )
        self.parser.add_argument(
            "--explain",
            action="store_true",
            help="Include detailed explanations"
        )
        self.parser.add_argument(
            "--output",
            help="Output file path",
            default=None
        )
        self.parser.add_argument(
            "--output-csv",
            help="Output results to CSV",
            default=None
        )
        self.parser.add_argument(
            "--export-json",
            nargs='?',
            const='scan_results.json', # Default filename if no arg provided
            default=None,
            metavar='FILEPATH',
            help="Export to JSON file"
        )
        self.parser.add_argument(
            "--json-stdout",
            action="store_true",
            help="JSON to stdout"
        )
        self.parser.add_argument(
            "-f", "--format",
            choices=['json', 'table'],
            default='table',
            help="Output format"
        )

    def test_parse_export_json_default_const(self):
        """Test --export-json uses default const when no value is given."""
        args = self.parser.parse_args(["some_file.py", "--export-json"])
        self.assertEqual(args.export_json, "scan_results.json")
        self.assertFalse(args.json_stdout)

    def test_parse_export_json_with_custom_path(self):
        """Test --export-json with a custom file path."""
        custom_path = "custom/output/dir/results.json"
        args = self.parser.parse_args(["some_file.py", "--export-json", custom_path])
        self.assertEqual(args.export_json, custom_path)
        self.assertFalse(args.json_stdout)

    def test_parse_json_stdout(self):
        """Test --json-stdout sets the flag correctly."""
        args = self.parser.parse_args(["some_file.py", "--json-stdout"])
        self.assertTrue(args.json_stdout)
        self.assertIsNone(args.export_json) # Should be None if --json-stdout is primary

    def test_parse_no_json_flags(self):
        """Test default behavior when no JSON flags are present."""
        args = self.parser.parse_args(["some_file.py"])
        self.assertIsNone(args.export_json)
        self.assertFalse(args.json_stdout)
        self.assertEqual(args.format, "table") # Default format

    def test_parse_export_json_and_json_stdout_stdout_priority(self):
        """Test --json-stdout takes priority if both it and --export-json are present."""
        # The cli.py logic prioritizes json_stdout if present
        args = self.parser.parse_args(["some_file.py", "--export-json", "file.json", "--json-stdout"])
        self.assertTrue(args.json_stdout)
        self.assertEqual(args.export_json, "file.json") # export_json still parsed but json_stdout controls output

    def test_parse_old_format_json_with_new_flags(self):
        """Test how old --format=json interacts with new flags."""
        # If --json-stdout is present, it should take precedence.
        args = self.parser.parse_args(["some_file.py", "--format", "json", "--json-stdout"])
        self.assertTrue(args.json_stdout)
        self.assertEqual(args.format, "json")

        # If --export-json is present, it should take precedence over just --format=json for output control.
        args = self.parser.parse_args(["some_file.py", "--format", "json", "--export-json", "out.json"])
        self.assertEqual(args.export_json, "out.json")
        self.assertFalse(args.json_stdout)
        self.assertEqual(args.format, "json")

    def test_parse_old_format_table_default(self):
        """Test old --format defaults to table."""
        args = self.parser.parse_args(["some_file.py"])
        self.assertEqual(args.format, "table")


class TestCliOutputLogic(unittest.TestCase):
    """Tests for the output formatting logic in cli.py's main function."""

    def setUp(self):
        # Mock dependencies for cli.main()
        self.mock_scan_file = mock.patch('agent_security.cli.scan_file').start()
        self.mock_scan_git_repository = mock.patch('agent_security.cli.scan_git_repository').start()
        self.mock_load_ignored_findings = mock.patch('agent_security.cli.load_ignored_findings').start()
        self.mock_console_print = mock.patch('agent_security.cli.console.print').start()
        self.mock_sys_stdout_write = mock.patch('sys.stdout.write').start()
        self.mock_open = mock.patch('builtins.open', new_callable=mock.mock_open).start()
        self.mock_json_dumps = mock.patch('json.dumps', side_effect=json.dumps).start() # Use real dumps but track calls
        self.mock_format_results_as_table = mock.patch('agent_security.cli.format_results_as_table').start()
        self.mock_generate_csv_report = mock.patch('agent_security.cli.generate_csv_report').start()
        
        # Default return for load_ignored_findings
        self.mock_load_ignored_findings.return_value = set()
        # Default return for scan_file (single file scan)
        self.mock_scan_file.return_value = SAMPLE_REPORT_SINGLE_FILE

        # Mock Path.is_file and Path.is_dir
        self.mock_path_is_file = mock.patch('pathlib.Path.is_file').start()
        self.mock_path_is_dir = mock.patch('pathlib.Path.is_dir').start()
        self.mock_path_rglob = mock.patch('pathlib.Path.rglob').start()

        # Default path behaviors
        self.mock_path_is_file.return_value = True
        self.mock_path_is_dir.return_value = False
        
        # Ensure cli.console is the mock we want for cli.main's global console
        # This is a bit tricky as cli.py defines its own 'console'.
        # We are mocking 'agent_security.cli.console.print' which should catch it.
        # And format_results_as_table is passed cli.console, so we mock that function.

    def tearDown(self):
        mock.patch.stopall()

    def test_default_table_output_single_file(self):
        """Test default table output for a single file scan."""
        cli.main(["test_file.py"])
        self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("."))
        self.mock_format_results_as_table.assert_called_once()
        
        # Check the arguments passed to format_results_as_table
        # First arg is findings_list, second is console instance
        args, _ = self.mock_format_results_as_table.call_args
        self.assertEqual(args[0], FLAT_SAMPLE_FINDINGS_SINGLE)
        # Ensure the console instance used by cli.main is passed
        self.assertTrue(isinstance(args[1], mock.MagicMock) or args[1] == cli.console)


    def test_default_table_output_empty_results(self):
        """Test table output when scan results are empty."""
        self.mock_scan_file.return_value = SAMPLE_REPORT_EMPTY
        cli.main(["empty_file.py"])
        self.mock_scan_file.assert_called_once_with("empty_file.py", set(), Path("."))
        self.mock_format_results_as_table.assert_called_once()
        args, _ = self.mock_format_results_as_table.call_args
        self.assertEqual(args[0], FLAT_SAMPLE_FINDINGS_EMPTY)


    def test_json_to_stdout_output(self):
        """Test JSON output to stdout."""
        cli.main(["test_file.py", "--json-stdout"])
        self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("."))
        
        expected_json_str = json.dumps(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2) + '\n'
        self.mock_sys_stdout_write.assert_called_once_with(expected_json_str)
        self.mock_json_dumps.assert_called_with(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2)
        self.mock_format_results_as_table.assert_not_called()

    def test_json_to_file_output_default_path(self):
        """Test JSON output to the default file path (scan_results.json)."""
        cli.main(["test_file.py", "--export-json"])
        self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("."))
        
        expected_filepath = "scan_results.json"
        self.mock_open.assert_called_once_with(expected_filepath, "w", encoding="utf-8")
        
        # Get the file handle mock from mock_open
        file_handle_mock = self.mock_open.return_value.__enter__.return_value
        expected_json_str = json.dumps(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2)
        file_handle_mock.write.assert_called_once_with(expected_json_str)
        
        self.mock_json_dumps.assert_called_with(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2)
        self.mock_console_print.assert_any_call(f"Results exported to [green]{expected_filepath}[/green]")
        self.mock_format_results_as_table.assert_not_called()
        self.mock_sys_stdout_write.assert_not_called() # Should not write to stdout if exporting to file

    def test_json_to_file_output_custom_path(self):
        """Test JSON output to a custom file path."""
        custom_filepath = "my_custom_results/output.json"
        cli.main(["test_file.py", "--export-json", custom_filepath])
        self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("."))
        
        self.mock_open.assert_called_once_with(custom_filepath, "w", encoding="utf-8")
        file_handle_mock = self.mock_open.return_value.__enter__.return_value
        expected_json_str = json.dumps(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2)
        file_handle_mock.write.assert_called_once_with(expected_json_str)

        self.mock_json_dumps.assert_called_with(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2)
        self.mock_console_print.assert_any_call(f"Results exported to [green]{custom_filepath}[/green]")
        self.mock_format_results_as_table.assert_not_called()

    def test_json_to_stdout_takes_priority_over_export_json(self):
        """Test --json-stdout takes priority over --export-json for output."""
        cli.main(["test_file.py", "--export-json", "some_file.json", "--json-stdout"])
        self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("."))
        
        # Should write to stdout
        expected_json_str = json.dumps(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2) + '\n'
        self.mock_sys_stdout_write.assert_called_once_with(expected_json_str)
        
        # Should NOT try to open/write to "some_file.json"
        self.mock_open.assert_not_called()
        self.mock_console_print.assert_not_any_call(f"Results exported to [green]some_file.json[/green]")
        self.mock_format_results_as_table.assert_not_called()

    def test_csv_output_single_file(self):
        """Test CSV output for a single file scan."""
        csv_output_path = "output.csv"
        cli.main(["test_file.py", "--output-csv", csv_output_path])
        self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("."))
        
        # Check that generate_csv_report was called with correct arguments
        self.mock_generate_csv_report.assert_called_once()
        args, _ = self.mock_generate_csv_report.call_args
        findings_list, output_path = args
        
        # Verify findings list structure matches expected format
        self.assertEqual(findings_list, FLAT_SAMPLE_FINDINGS_SINGLE)
        self.assertEqual(output_path, csv_output_path)
        
        # Verify default table output still occurs
        self.mock_format_results_as_table.assert_called_once()

    def test_csv_output_empty_results(self):
        """Test CSV output when scan results are empty."""
        self.mock_scan_file.return_value = SAMPLE_REPORT_EMPTY
        csv_output_path = "empty_output.csv"
        cli.main(["empty_file.py", "--output-csv", csv_output_path])
        
        # Check generate_csv_report was called with empty findings list
        self.mock_generate_csv_report.assert_called_once()
        args, _ = self.mock_generate_csv_report.call_args
        findings_list, output_path = args
        
        self.assertEqual(findings_list, FLAT_SAMPLE_FINDINGS_EMPTY)
        self.assertEqual(output_path, csv_output_path)

    def test_csv_output_with_json_stdout(self):
        """Test CSV output combined with JSON stdout output."""
        csv_output_path = "output.csv"
        cli.main(["test_file.py", "--output-csv", csv_output_path, "--json-stdout"])
        
        # Both CSV and JSON output should be generated
        self.mock_generate_csv_report.assert_called_once()
        expected_json_str = json.dumps(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2) + '\n'
        self.mock_sys_stdout_write.assert_called_once_with(expected_json_str)

    def test_csv_output_with_json_export(self):
        """Test CSV output combined with JSON file export."""
        csv_output_path = "output.csv"
        json_output_path = "output.json"
        cli.main(["test_file.py", "--output-csv", csv_output_path, "--export-json", json_output_path])
        
        # Both CSV and JSON files should be generated
        self.mock_generate_csv_report.assert_called_once()
        self.mock_open.assert_any_call(json_output_path, "w", encoding="utf-8")
        
        # Verify JSON content
        file_handle = self.mock_open.return_value.__enter__.return_value
        expected_json_str = json.dumps(JSON_OUTPUT_SINGLE_FILE_SCAN, indent=2)
        file_handle.write.assert_any_call(expected_json_str)

    # Placeholder for testing the actual format_results_as_table function's output
    # This would involve capturing Rich's output, which can be complex.
    # For now, we're testing that it's *called* correctly.
    # A more direct test of format_results_as_table would be in a separate class.

# It would also be good to have a separate test class for the `format_results_as_table`
# function itself, to check the Rich table construction more directly if needed,
# though mocking Rich's Console and Table for exact output string matching is non-trivial.


class TestFormatResultsAsTable(unittest.TestCase):
    """Directly tests the cli.format_results_as_table function."""

    def setUp(self):
        self.mock_console = mock.MagicMock(spec=cli.Console)
        # To inspect calls to table.add_row, we need to mock the Table object
        self.mock_table_instance = mock.MagicMock(spec=cli.Table)
        self.mock_table_class = mock.patch('agent_security.cli.Table', return_value=self.mock_table_instance).start()

    def tearDown(self):
        mock.patch.stopall()

    def test_format_results_as_table_no_findings(self):
        """Test that 'No vulnerabilities found.' is printed for empty findings list."""
        cli.format_results_as_table([], self.mock_console)
        self.mock_console.print.assert_called_once_with("No vulnerabilities found.")
        self.mock_table_class.assert_not_called() # No table should be created

    def test_format_results_as_table_with_findings(self):
        """Test table creation and row population with sample findings."""
        sample_flat_findings = [
            {
                "file_path": "file1.py",
                "line_number": 10,
                "pattern": "os.system",
                "risk_level": "CRITICAL",
                "security_info": {"description": "Desc1"}
            },
            {
                "file_path": "file2.yaml",
                "line_number": 5,
                "pattern": "some_tool",
                "risk_level": "HIGH",
                "security_info": {"description": "Desc2"}
            },
            { # Finding with no line number
                "file_path": "file3.py",
                "line_number": None,
                "pattern": "another_tool",
                "risk_level": "MEDIUM",
                "security_info": {"description": "Desc3"}
            }
        ]

        # Mock TOOL_RISKS used internally by format_results_as_table
        with mock.patch.dict(cli.TOOL_RISKS, {
            "os.system": SecurityInfo(
                risk_level=RiskLevel.CRITICAL,
                pattern=re.compile("os.system"),
                description="Arbitrary command execution",
                impact="",
                remediation=""
            ),
            "some_tool": SecurityInfo(
                risk_level=RiskLevel.HIGH,
                pattern=re.compile("some_tool"),
                description="Some tool description",
                impact="",
                remediation=""
            ),
            "another_tool": SecurityInfo(
                risk_level=RiskLevel.MEDIUM,
                pattern=re.compile("another_tool"),
                description="Another tool description",
                impact="",
                remediation=""
            ),
        }, clear=True):
            cli.format_results_as_table(sample_flat_findings, self.mock_console)

        self.mock_table_class.assert_called_once_with(
            title="Scan Results",
            show_lines=True,
            padding=(0, 1),
            expand=True
        )

        # Check columns - order and names
        expected_columns = [
            mock.call("File", style="cyan", no_wrap=False, overflow="fold"),
            mock.call("Line", justify="right", width=5),
            mock.call("Description", style="italic", no_wrap=False, overflow="fold"),
            mock.call("Confidence", width=10)
        ]
        self.mock_table_instance.add_column.assert_has_calls(expected_columns, any_order=False)

        # Check rows - data passed to add_row
        expected_rows = [
            mock.call("file1.py", "10", "Arbitrary command execution", "CRITICAL"),
            mock.call("file2.yaml", "5", "Some tool description", "HIGH"),
            mock.call("file3.py", "N/A", "Another tool description", "MEDIUM"),
        ]
        self.mock_table_instance.add_row.assert_has_calls(expected_rows, any_order=False)
        self.assertEqual(self.mock_table_instance.add_row.call_count, 3)

        # Check that the table is printed
        self.mock_console.print.assert_called_once_with(self.mock_table_instance)

    def test_format_results_as_table_finding_with_comma_in_description(self):
        """Test table output when a finding's description contains a comma."""
        finding_with_comma = [
            {
                "file_path": "file_comma.py",
                "line_number": 15,
                "pattern": "comma_tool",
                "risk_level": "LOW",
                "security_info": {"description": "This, is, a, description, with, commas"}
            }
        ]
        with mock.patch.dict(cli.TOOL_RISKS, {
            "comma_tool": SecurityInfo(
                risk_level=RiskLevel.LOW,
                pattern=re.compile("comma_tool"),
                description="This, is, a, description, with, commas",
                impact="",
                remediation=""
            ),
        }, clear=True):
            cli.format_results_as_table(finding_with_comma, self.mock_console)

        self.mock_table_instance.add_row.assert_called_once_with(
            "file_comma.py", "15", "This, is, a, description, with, commas", "LOW"
        )
        self.mock_console.print.assert_called_once_with(self.mock_table_instance)


class TestGenerateCSVReport(unittest.TestCase):
    """Tests for the CSV report generation functionality."""

    def setUp(self):
        self.mock_open = mock.patch('builtins.open', new_callable=mock.mock_open).start()
        self.mock_csv_writer = mock.MagicMock()
        self.mock_csv = mock.patch('csv.writer', return_value=self.mock_csv_writer).start()
        self.mock_print = mock.patch('builtins.print').start()

    def tearDown(self):
        mock.patch.stopall()

    def test_generate_csv_empty_findings(self):
        """Test CSV generation with empty findings list."""
        cli.generate_csv_report([], "empty.csv")
        
        # Check file was opened correctly
        self.mock_open.assert_called_once_with("empty.csv", "w", newline="", encoding="utf-8")
        
        # Check header was written
        expected_header = [
            "file_path",
            "line_number",
            "finding_type",
            "severity",
            "description",
            "pattern_id",
            "impact",
            "remediation",
        ]
        self.mock_csv_writer.writerow.assert_called_once_with(expected_header)
        
        # Check success message
        self.mock_print.assert_called_once_with("No findings detected. Empty CSV created at empty.csv")

    def test_generate_csv_with_findings(self):
        """Test CSV generation with sample findings."""
        findings = [
            {
                "file_path": "test_file.py",
                "line_number": 10,
                "pattern": "os.system",
                "risk_level": "CRITICAL",
                "context": "os.system('rm -rf /')",
                "security_info": {
                    "description": "Allows arbitrary command execution.",
                    "impact": "System compromise.",
                    "remediation": "Avoid os.system."
                }
            }
        ]
        
        cli.generate_csv_report(findings, "output.csv")
        
        # Check file was opened correctly
        self.mock_open.assert_called_once_with("output.csv", "w", newline="", encoding="utf-8")
        
        # Check header and data were written
        calls = self.mock_csv_writer.writerow.call_args_list
        expected_header = [
            "file_path",
            "line_number",
            "finding_type",
            "severity",
            "description",
            "pattern_id",
            "impact",
            "remediation",
        ]
        self.assertEqual(calls[0][0][0], expected_header)
        
        # Check data row
        expected_data = [
            "test_file.py",
            10,
            "os.system",
            "CRITICAL",
            "Allows arbitrary command execution.",
            "System compromise. - os.system('rm -rf /')",
            "Avoid os.system.",
            "os.system"
        ]
        self.assertEqual(calls[1][0][0], expected_data)
        
        # Check success message
        self.mock_print.assert_called_once_with("CSV report successfully generated at: output.csv")

    def test_generate_csv_with_missing_fields(self):
        """Test CSV generation with findings that have missing fields."""
        findings = [
            {
                "file_path": "test_file.py",
                "pattern": "os.system",
                # Missing line_number and other fields
                "security_info": None
            }
        ]
        
        cli.generate_csv_report(findings, "missing_fields.csv")
        
        # Check file was opened correctly
        self.mock_open.assert_called_once_with("missing_fields.csv", "w", newline="", encoding="utf-8")
        
        # Check data row handles missing fields gracefully
        calls = self.mock_csv_writer.writerow.call_args_list
        data_row = calls[1][0][0]
        self.assertEqual(data_row[0], "test_file.py")  # file_path present
        self.assertEqual(data_row[1], "")  # line_number missing
        self.assertEqual(data_row[2], "os.system")  # pattern present
        self.assertEqual(data_row[4], "")  # description missing
        
        # Check success message
        self.mock_print.assert_called_once_with("CSV report successfully generated at: missing_fields.csv")

    def test_generate_csv_io_error(self):
        """Test CSV generation when an IO error occurs."""
        self.mock_open.side_effect = IOError("Permission denied")
        
        cli.generate_csv_report([], "error.csv")
        
        # Check error message
        self.mock_print.assert_called_once_with("Error: Could not write CSV file to error.csv. Reason: Permission denied")


if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)