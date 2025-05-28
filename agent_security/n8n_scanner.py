"""
Scanner for n8n workflow files.
"""
import json
import logging
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Set, Tuple

from .models import RiskLevel, SecurityFinding, SecurityInfo, SecurityReport
from .patterns.n8n_patterns import N8N_PATTERNS

logger = logging.getLogger(__name__)

# Copied from scanner.py to avoid circular dependency.
# Omitted sanitize_error call due to its unknown origin in this context.
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
        # Corrected tuple unpacking: was (pattern, line, path), should be (path, line, pattern) based on load_ignored_findings
        for ignored_file_rel_path, ignored_line_num, ignored_pattern_str in ignored_set:
            if (ignored_pattern_str == finding.pattern and
                (ignored_line_num is None or ignored_line_num == finding.line_number) and
                (ignored_file_rel_path is None or ignored_file_rel_path == relative_path)):
                return True
                
        return False
    except Exception as e:
        # logger.error(f"Error checking if finding is ignored: {sanitize_error(e)}") # sanitize_error definition is missing
        logger.error(f"Error checking if finding is ignored: {e}")
        return False

def scan_n8n_workflow_content(content: str, file_path: str, ignored_findings: Set[Tuple[str, int, str]], base_path: Path) -> SecurityReport:
    """
    Scan n8n workflow (JSON) content for security issues.
    """
    report = SecurityReport(
        findings=[],
        overall_risk=RiskLevel.LOW,
        file_path=str(file_path),
        timestamp=datetime.now().isoformat() # datetime not imported
    )

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {file_path}: {e}")
        error_finding = SecurityFinding(
            pattern="json_decode_error",
            risk_level=RiskLevel.MEDIUM,
            line_number=getattr(e, 'lineno', 1),
            context=f"JSON Decode Error: {e.msg}",
            security_info=SecurityInfo(
                name="JSON Decode Error",
                risk_level=RiskLevel.MEDIUM,
                description=f"Failed to parse JSON content: {e.msg}",
                impact="The workflow file is malformed and cannot be scanned properly.",
                remediation="Ensure the n8n workflow JSON is well-formed and valid.",
            ),
            file_path=file_path
        )
        if not is_finding_ignored(error_finding, ignored_findings, base_path):
            report.findings.append(error_finding)
        report.overall_risk = max(report.overall_risk, RiskLevel.MEDIUM)
        return report

    if not isinstance(data, dict) or 'nodes' not in data or not isinstance(data['nodes'], list):
        logger.warning(f"No 'nodes' list found in {file_path}, or it's not a list. Skipping n8n scan for this file.")
        return report

    content_lines = content.splitlines()

    for node_index, node in enumerate(data.get('nodes', [])):
        if not isinstance(node, dict):
            logger.warning(f"Node at index {node_index} in {file_path} is not a dictionary. Skipping.")
            continue

        node_type = node.get('type')
        node_parameters = node.get('parameters', {})
        node_name = node.get('name', f"Unnamed Node {node_index+1}")
        node_id = node.get('id') # Used for trying to find line number

        current_node_line_number = 1 # Default line number
        if node_id: # Try to find a more accurate line number
            search_str_id = f'"id": "{node_id}"'
            search_str_name = f'"name": "{node_name}"' 
            for i, line_text in enumerate(content_lines):
                if search_str_id in line_text or (node_name != f"Unnamed Node {node_index+1}" and search_str_name in line_text) :
                    current_node_line_number = i + 1
                    break
        
        if node_type == 'n8n-nodes-base.code':
            js_code = node_parameters.get('jsCode', '')
            if isinstance(js_code, str) and js_code:
                pattern_info_env = N8N_PATTERNS['n8n_code_node_env_access']
                if pattern_info_env.pattern.search(js_code):
                    finding = SecurityFinding(
                        pattern='n8n_code_node_env_access',
                        risk_level=pattern_info_env.risk_level,
                        line_number=current_node_line_number,
                        context=f"In Code Node '{node_name}': Accessing process.env.\nSnippet: {textwrap.shorten(js_code, width=150, placeholder='...')}",
                        security_info=pattern_info_env,
                        file_path=file_path
                    )
                    if not is_finding_ignored(finding, ignored_findings, base_path):
                        report.findings.append(finding)

                pattern_info_eval = N8N_PATTERNS['n8n_code_node_eval_usage']
                if pattern_info_eval.pattern.search(js_code):
                    finding = SecurityFinding(
                        pattern='n8n_code_node_eval_usage',
                        risk_level=pattern_info_eval.risk_level,
                        line_number=current_node_line_number,
                        context=f"In Code Node '{node_name}': Use of eval().\nSnippet: {textwrap.shorten(js_code, width=150, placeholder='...')}",
                        security_info=pattern_info_eval,
                        file_path=file_path
                    )
                    if not is_finding_ignored(finding, ignored_findings, base_path):
                        report.findings.append(finding)

        elif node_type == 'n8n-nodes-base.executeCommand':
            pattern_info_exec = N8N_PATTERNS['n8n_execute_command_node_usage']
            command_str = node_parameters.get('command', '')
            context_exec = f"Execute Command Node '{node_name}' is used."
            if command_str:
                 context_exec += f"\nCommand: {textwrap.shorten(str(command_str), width=150, placeholder='...')}"

            finding = SecurityFinding(
                pattern='n8n_execute_command_node_usage',
                risk_level=pattern_info_exec.risk_level,
                line_number=current_node_line_number,
                context=context_exec,
                security_info=pattern_info_exec,
                file_path=file_path
            )
            if not is_finding_ignored(finding, ignored_findings, base_path):
                report.findings.append(finding)

        elif node_type == 'n8n-nodes-base.httpRequest':
            url = node_parameters.get('url', '')
            if isinstance(url, str) and url:
                pattern_info_ssrf = N8N_PATTERNS['n8n_ssrf_http_request_node']
                if pattern_info_ssrf.pattern.search(url):
                    finding = SecurityFinding(
                        pattern='n8n_ssrf_http_request_node',
                        risk_level=pattern_info_ssrf.risk_level,
                        line_number=current_node_line_number,
                        context=f"In HTTP Request Node '{node_name}', potential SSRF in URL: {url}",
                        security_info=pattern_info_ssrf,
                        file_path=file_path
                    )
                    if not is_finding_ignored(finding, ignored_findings, base_path):
                        report.findings.append(finding)
        
        pattern_info_generic_secret = N8N_PATTERNS['n8n_hardcoded_api_key_generic']
        if isinstance(node_parameters, dict):
            for param_key, param_value in node_parameters.items():
                if node_type == 'n8n-nodes-base.code' and param_key == 'jsCode':
                    continue
                if isinstance(param_value, str) and param_value: 
                    if pattern_info_generic_secret.pattern.search(param_value):
                        finding = SecurityFinding(
                            pattern='n8n_hardcoded_api_key_generic',
                            risk_level=pattern_info_generic_secret.risk_level,
                            line_number=current_node_line_number,
                            context=f"In Node '{node_name}' (type: {node_type}), parameter '{param_key}' contains potential hardcoded secret: ...'{textwrap.shorten(param_value, width=100, placeholder='...')}'...",
                            security_info=pattern_info_generic_secret,
                            file_path=file_path
                        )
                        if not is_finding_ignored(finding, ignored_findings, base_path):
                            report.findings.append(finding)
    
    if report.findings:
        risk_levels = [f.risk_level for f in report.findings]
        report.overall_risk = max(risk_levels)

    return report
