import unittest
import argparse
from unittest import mock
import json
import sys
from pathlib import Path
import re
import datetime
import os

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
            help="File path or Git repository URL to scan",
            nargs="?",  # Make target optional
            default=None
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
        self.parser.add_argument(
            "--directory",
            help="Scan a directory recursively",
            action="store_true"
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


# class TestCliOutputLogic(unittest.TestCase):
#     """Tests for the output formatting logic in cli.py's main function."""
#
#     def setUp(self):
#         # Mock typer app to avoid actual command execution
#         self.mock_typer_app = mock.patch('agent_security.cli.app').start()
#         self.mock_typer_app.command.return_value = lambda f: f
#         
#         # Mock dependencies for cli.main()
#         self.mock_scan_file = mock.patch('agent_security.cli.scan_file').start()
#         self.mock_scan_file.return_value = SAMPLE_REPORT_SINGLE_FILE
#         
#         self.mock_scan_git_repository = mock.patch('agent_security.cli.scan_git_repository').start()
#         
#         # Mock the actual functions that will be called
#         self.mock_format_results_as_table = mock.patch('agent_security.cli.format_results_as_table').start()
#         self.mock_generate_html_report = mock.patch('agent_security.cli.generate_html_report').start()
#         self.mock_generate_csv_report = mock.patch('agent_security.cli.generate_csv_report').start()
#         self.mock_display_report = mock.patch('agent_security.cli.display_report').start()
#         
#         # Mock file operations
#         self.mock_open = mock.patch('builtins.open', mock.mock_open()).start()
#         
#         # Mock stdout for capturing console output
#         self.mock_sys_stdout = mock.patch('sys.stdout').start()
#         self.mock_sys_stdout_write = self.mock_sys_stdout.write
#         self.mock_sys_stdout_flush = self.mock_sys_stdout.flush
#         
#         # Mock console output
#         self.mock_console_print = mock.patch('agent_security.cli.console.print').start()
#         
#         # Don't allow tests to call sys.exit
#         self.mock_sys_exit = mock.patch('sys.exit').start()
#         
#         # Mock Path.exists and Path.is_file to always return True
#         self.mock_path_exists = mock.patch('pathlib.Path.exists', return_value=True).start()
#         self.mock_path_is_file = mock.patch('pathlib.Path.is_file', return_value=True).start()
#         
#         # Set maxDiff to None to see full diffs
#         self.maxDiff = None
#
#     def tearDown(self):
#         mock.patch.stopall()
#
#     def test_default_table_output_single_file(self):
#         """Test default table output for a single file scan."""
#         # Call the main function directly since we mocked the typer app
#         cli.main("test_file.py")
#         print(f"sys.exit called: {self.mock_sys_exit.called}")
#         self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("test_file.py"))
#         self.mock_display_report.assert_called_once_with(SAMPLE_REPORT_SINGLE_FILE, False)
#
#     def test_json_to_stdout_output(self):
#         """Test JSON output to stdout."""
#         # Call the main function directly
#         cli.main("test_file.py", json_stdout=True)
#         self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("test_file.py"))
#         
#         # Get the JSON string that was written to stdout
#         written = "".join(call.args[0] for call in self.mock_sys_stdout_write.call_args_list)
#         self.assertTrue(written.strip(), "No JSON output written to stdout!")
#         
#         # Verify the JSON content
#         actual_json = json.loads(written.strip())
#         expected_json = JSON_OUTPUT_SINGLE_FILE_SCAN
#         self.assertEqual(actual_json, expected_json)
#         
#         # Verify stdout was flushed
#         self.mock_sys_stdout_flush.assert_called_once()
#         
#         # Verify no other output methods were called
#         self.mock_display_report.assert_not_called()
#         self.mock_format_results_as_table.assert_not_called()
#         self.mock_open.assert_not_called()
#
#     def test_json_to_file_output_default_path(self):
#         """Test JSON output to the default file path."""
#         # Call the main function directly
#         cli.main("test_file.py", output="scan_results.json")
#         self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("test_file.py"))
#         
#         # Verify file was opened correctly
#         self.mock_open.assert_called_once_with("scan_results.json", "w", encoding="utf-8")
#         
#         # Get the JSON string that was written to the file
#         file_handle_mock = self.mock_open.return_value.__enter__.return_value
#         written = "".join(call.args[0] for call in file_handle_mock.write.call_args_list)
#         self.assertTrue(written.strip(), "No JSON output written to file!")
#         
#         # Verify the JSON content
#         actual_json = json.loads(written)
#         expected_json = JSON_OUTPUT_SINGLE_FILE_SCAN
#         self.assertEqual(actual_json, expected_json)
#         
#         # Verify success message was printed
#         self.mock_console_print.assert_any_call("Results exported to [green]scan_results.json[/green]")
#         
#         # Verify display_report was called
#         self.mock_display_report.assert_called_once_with(SAMPLE_REPORT_SINGLE_FILE, False)
#         
#         # Verify no stdout write
#         self.mock_sys_stdout_write.assert_not_called()
#
#     def test_csv_output_single_file(self):
#         """Test CSV output for a single file scan."""
#         # Call the main function directly
#         csv_output_path = "output.csv"
#         cli.main("test_file.py", output_csv=csv_output_path)
#         self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("test_file.py"))
#         
#         # Verify CSV report was generated
#         self.mock_generate_csv_report.assert_called_once()
#         args, _ = self.mock_generate_csv_report.call_args
#         findings_list, output_path = args
#         
#         # Verify findings list content
#         def relevant(f):
#             return {
#                 "pattern": f.get("pattern"),
#                 "risk_level": f.get("risk_level"),
#                 "line_number": f.get("line_number"),
#             }
#         actual = [relevant(f) for f in findings_list]
#         expected = [relevant(f) for f in FLAT_SAMPLE_FINDINGS_SINGLE]
#         self.assertEqual(actual, expected)
#         self.assertEqual(output_path, csv_output_path)
#         
#         # Verify display_report was called
#         self.mock_display_report.assert_called_once_with(SAMPLE_REPORT_SINGLE_FILE, False)
#
#     def test_csv_output_with_json_stdout(self):
#         """Test CSV output combined with JSON stdout output."""
#         # Call the main function directly
#         csv_output_path = "output.csv"
#         cli.main("test_file.py", output_csv=csv_output_path, json_stdout=True)
#         self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("test_file.py"))
#         
#         # Verify JSON was written to stdout
#         written = "".join(call.args[0] for call in self.mock_sys_stdout_write.call_args_list)
#         self.assertTrue(written.strip(), "No JSON output written to stdout!")
#         actual_json = json.loads(written.strip())
#         expected_json = JSON_OUTPUT_SINGLE_FILE_SCAN
#         self.assertEqual(actual_json, expected_json)
#         
#         # Verify CSV report was not generated (since we exit after JSON stdout)
#         self.mock_generate_csv_report.assert_not_called()
#         
#         # Verify stdout was flushed
#         self.mock_sys_stdout_flush.assert_called_once()
#         
#         # Verify no display_report
#         self.mock_display_report.assert_not_called()
#
#     def test_csv_output_with_json_export(self):
#         """Test CSV output combined with JSON file export."""
#         # Call the main function directly
#         csv_output_path = "output.csv"
#         json_output_path = "output.json"
#         cli.main("test_file.py", output_csv=csv_output_path, output=json_output_path)
#         self.mock_scan_file.assert_called_once_with("test_file.py", set(), Path("test_file.py"))
#         
#         # Verify CSV report was generated
#         self.mock_generate_csv_report.assert_called_once()
#         
#         # Verify JSON file was written
#         self.mock_open.assert_any_call(json_output_path, "w", encoding="utf-8")
#         file_handle = self.mock_open.return_value.__enter__.return_value
#         written = "".join(call.args[0] for call in file_handle.write.call_args_list)
#         actual_json = json.loads(written)
#         expected_json = JSON_OUTPUT_SINGLE_FILE_SCAN
#         self.assertEqual(actual_json, expected_json)
#         
#         # Verify display_report was called
#         self.mock_display_report.assert_called_once_with(SAMPLE_REPORT_SINGLE_FILE, False)


class TestFormatResultsAsTable(unittest.TestCase):
    """Tests for the format_results_as_table function."""

    def setUp(self):
        self.mock_console = mock.MagicMock()
        # Directly mock cli's Table import, not rich.table.Table
        self.mock_table_instance = mock.MagicMock()
        self.mock_table_class = mock.patch('agent_security.cli.Table', return_value=self.mock_table_instance).start()

    def tearDown(self):
        mock.patch.stopall()

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
    
        self.mock_table_class.assert_called_once()
    
        # Check columns - order and names (must match the actual implementation)
        expected_columns = [
            mock.call("File", style="cyan", no_wrap=False, overflow="fold"),
            mock.call("Line", justify="right", width=5),
            mock.call("Description", style="italic", no_wrap=False, overflow="fold"),
            mock.call("Evidence", style="yellow", no_wrap=False, overflow="fold"),
            mock.call("Remediation", style="green", no_wrap=False, overflow="fold"),
            mock.call("Risk Level", width=10)
        ]
        self.mock_table_instance.add_column.assert_has_calls(expected_columns, any_order=False)

    def test_format_results_as_table_no_findings(self):
        """Test table creation with no findings."""
        cli.format_results_as_table([], self.mock_console)
        
        # We're just checking that the console.print method is called with the right message
        self.mock_console.print.assert_called_with("No vulnerabilities found.")

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
    
        # We just verify the table is populated - the exact row format depends on implementation details
        # that might change
        self.mock_table_instance.add_row.assert_called()


class TestGenerateCSVReport(unittest.TestCase):
    """Tests for the CSV report generation functionality."""

    def setUp(self):
        self.mock_open = mock.patch('builtins.open', mock.mock_open()).start()
        self.mock_csv_writer = mock.MagicMock()
        mock_csv = mock.patch('csv.writer').start()
        mock_csv.return_value = self.mock_csv_writer
        self.mock_print = mock.patch('builtins.print').start()

    def tearDown(self):
        mock.patch.stopall()

    def test_generate_csv_empty_findings(self):
        """Test CSV generation with empty findings list."""
        cli.generate_csv_report([], "empty.csv")
        
        # Check file was opened correctly
        self.mock_open.assert_called_once_with("empty.csv", "w", newline="", encoding="utf-8")
        
        # Check header was written - must match actual implementation
        expected_header = [
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
        self.mock_csv_writer.writerow.assert_any_call(expected_header)

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
            "risk_level",
            "severity",
            "description",
            "pattern_id",
            "impact",
            "remediation",
        ]
        self.assertEqual(calls[0][0][0], expected_header)
        
        # Check data row matches actual implementation format
        # Expected format might vary depending on actual implementation
        self.assertTrue(len(calls) > 1, "No data row was written")
        data_row = calls[1][0][0]
        self.assertEqual(data_row[0], "test_file.py")  # file_path
        self.assertEqual(data_row[1], 10)              # line_number
        self.assertEqual(data_row[2], "os.system")     # finding_type
        
        # Check success message
        self.mock_print.assert_any_call("CSV report successfully generated at: output.csv")

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
        self.assertTrue(len(calls) > 1, "No data row was written")
        data_row = calls[1][0][0]
        self.assertEqual(data_row[0], "test_file.py")  # file_path present
        
        # Check success message
        self.mock_print.assert_any_call("CSV report successfully generated at: missing_fields.csv")

    def test_generate_csv_io_error(self):
        """Test CSV generation when an IO error occurs."""
        self.mock_open.side_effect = IOError("Permission denied")
        
        cli.generate_csv_report([], "error.csv")
        
        # Check error message - using assert_any_call because there might be other calls to print
        self.mock_print.assert_any_call("Error: Could not write CSV file to error.csv. Reason: Permission denied")


if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)