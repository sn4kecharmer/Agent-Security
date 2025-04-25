"""
File scanning functionality for the security scanner.
"""

import ast
import yaml
import logging
import ruamel.yaml
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from .models import SecurityReport, SecurityInfo, ToolUsage
from .patterns import TOOL_RISKS, YAML_TOOL_PATTERNS

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class ToolVisitor(ast.NodeVisitor):
    """AST visitor to find tool usage in Python code."""
    
    def __init__(self, report: SecurityReport):
        self.report = report
        
    def visit_Call(self, node: ast.Call):
        """Visit function/class calls to detect tool usage."""
        # Get the name of the called function/class
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        else:
            name = None
            
        if name:
            logger.debug(f"Checking call to: {name}")
            # Check each tool pattern
            for tool_name, security_info in TOOL_RISKS.items():
                if security_info.pattern.search(name):
                    # Get the line number and context
                    line_number = getattr(node, 'lineno', None)
                    context = ast.get_source_segment(self.source, node) if hasattr(self, 'source') else None
                    logger.debug(f"Found tool usage: {tool_name} at line {line_number}")
                    
                    # Create a tool usage report
                    tool_usage = ToolUsage(
                        name=tool_name,
                        security_info=security_info,
                        line_number=line_number,
                        context=context,
                        match=name
                    )
                    
                    self.report.add_tool_usage(tool_usage)
        
        # Continue visiting child nodes
        self.generic_visit(node)

def scan_python_file(file_path: str) -> SecurityReport:
    """
    Scan a Python file for potential security issues.
    
    Args:
        file_path: Path to the Python file
        
    Returns:
        SecurityReport containing findings
    """
    logger.debug(f"Scanning Python file: {file_path}")
    report = SecurityReport()
    
    try:
        # Read the entire file content first
        with open(file_path, 'r') as f:
            source = f.read()
            logger.debug(f"Successfully read file: {file_path}")
        
        # Parse the AST and run the visitor
        tree = ast.parse(source, filename=file_path)
        logger.debug("Successfully parsed AST")
        
        # Create and run the visitor
        visitor = ToolVisitor(report)
        visitor.source = source  # Set the source before visiting
        visitor.visit(tree)
        logger.debug("Completed AST visit")
            
    except Exception as e:
        logger.error(f"Error scanning Python file {file_path}: {e}", exc_info=True)
        
    return report

def get_yaml_line_numbers(content: str) -> Dict[str, int]:
    """Get line numbers for YAML keys."""
    line_numbers = {}
    try:
        for token in yaml.scan(content):
            if isinstance(token, yaml.ScalarToken):
                # Store the line number for this key
                line_numbers[token.value] = token.start_mark.line + 1
    except Exception as e:
        logger.error(f"Error scanning YAML tokens: {e}")
    return line_numbers

def scan_yaml_content(node: yaml.Node, report: SecurityReport, path: str = "", source_lines: List[str] = None, line_numbers: Dict[str, int] = None):
    """
    Recursively scan YAML content for security patterns.
    
    Args:
        node: YAML node to scan
        report: SecurityReport to update
        path: Current path in the YAML structure
        source_lines: Original source lines for context
        line_numbers: Mapping of YAML keys to line numbers
    """
    logger.debug(f"Scanning YAML content at path: {path}")
    
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key = key_node.value
            current_path = f"{path}.{key}" if path else key
            # Get line number from our mapping
            line_num = line_numbers.get(key) if line_numbers else None
            logger.debug(f"Checking key: {key} at path: {current_path} on line {line_num}")
            
            # Check the key against patterns
            for pattern_name, security_info in YAML_TOOL_PATTERNS.items():
                if security_info.pattern.search(str(key)):
                    logger.debug(f"Found pattern match: {pattern_name} for key: {key}")
                    # Get the context from the source lines
                    context_lines = []
                    if source_lines and line_num:
                        # Get a few lines of context
                        start = max(0, line_num - 2)
                        end = min(len(source_lines), line_num + 1)
                        context_lines = source_lines[start:end]
                    
                    tool_usage = ToolUsage(
                        name=f"YAML Tool: {current_path}",
                        security_info=security_info,
                        line_number=line_num,
                        context="\n".join(context_lines) if context_lines else None,
                        match=key
                    )
                    report.add_tool_usage(tool_usage)
            
            # Recursively scan nested content
            scan_yaml_content(value_node, report, current_path, source_lines, line_numbers)
            
    elif isinstance(node, yaml.SequenceNode):
        for i, item_node in enumerate(node.value):
            current_path = f"{path}[{i}]"
            scan_yaml_content(item_node, report, current_path, source_lines, line_numbers)
    
    elif isinstance(node, yaml.ScalarNode):
        # Check scalar values against patterns too
        value = node.value
        # Get line number from our mapping
        line_num = line_numbers.get(value) if line_numbers else None
        for pattern_name, security_info in YAML_TOOL_PATTERNS.items():
            if security_info.pattern.search(str(value)):
                logger.debug(f"Found pattern match in value: {pattern_name} for value: {value}")
                # Get the context from the source lines
                context_lines = []
                if source_lines and line_num:
                    # Get a few lines of context
                    start = max(0, line_num - 2)
                    end = min(len(source_lines), line_num + 1)
                    context_lines = source_lines[start:end]
                
                tool_usage = ToolUsage(
                    name=f"YAML Value: {path}",
                    security_info=security_info,
                    line_number=line_num,
                    context="\n".join(context_lines) if context_lines else None,
                    match=value
                )
                report.add_tool_usage(tool_usage)

def scan_yaml_file(file_path: str) -> SecurityReport:
    """
    Scan a YAML file for potential security issues.
    
    Args:
        file_path: Path to the YAML file
        
    Returns:
        SecurityReport containing findings
    """
    logger.debug(f"Scanning YAML file: {file_path}")
    report = SecurityReport()
    yaml = ruamel.yaml.YAML()
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            source_lines = content.splitlines()
            
            # Parse YAML with line numbers
            data = yaml.load(content)
            
            def scan_node(node, path=""):
                if isinstance(node, dict):
                    for key, value in node.items():
                        current_path = f"{path}.{key}" if path else key
                        # Get line number from ruamel.yaml metadata
                        line_num = None
                        if hasattr(key, 'lc'):
                            line_num = key.lc.line + 1  # Convert to 1-based line numbers
                        
                        logger.debug(f"Checking key: {key} at path: {current_path} on line {line_num}")
                        
                        # Check the key against patterns
                        for pattern_name, security_info in YAML_TOOL_PATTERNS.items():
                            if security_info.pattern.search(str(key)):
                                logger.debug(f"Found pattern match: {pattern_name} for key: {key}")
                                # Get the context from the source lines
                                context_lines = []
                                if source_lines and line_num:
                                    # Get a few lines of context
                                    start = max(0, line_num - 2)
                                    end = min(len(source_lines), line_num + 1)
                                    context_lines = source_lines[start:end]
                                
                                tool_usage = ToolUsage(
                                    name=f"YAML Tool: {current_path}",
                                    security_info=security_info,
                                    line_number=line_num,
                                    context="\n".join(context_lines) if context_lines else None,
                                    match=str(key)
                                )
                                report.add_tool_usage(tool_usage)
                        
                        # Recursively scan nested content
                        scan_node(value, current_path)
                
                elif isinstance(node, list):
                    for i, item in enumerate(node):
                        current_path = f"{path}[{i}]"
                        scan_node(item, current_path)
                
                elif isinstance(node, str):
                    # Check scalar values against patterns
                    for pattern_name, security_info in YAML_TOOL_PATTERNS.items():
                        if security_info.pattern.search(node):
                            logger.debug(f"Found pattern match in value: {pattern_name} for value: {node}")
                            # Get line number from ruamel.yaml metadata
                            line_num = None
                            if hasattr(node, 'lc'):
                                line_num = node.lc.line + 1
                            
                            # Get the context from the source lines
                            context_lines = []
                            if source_lines and line_num:
                                # Get a few lines of context
                                start = max(0, line_num - 2)
                                end = min(len(source_lines), line_num + 1)
                                context_lines = source_lines[start:end]
                            
                            tool_usage = ToolUsage(
                                name=f"YAML Value: {path}",
                                security_info=security_info,
                                line_number=line_num,
                                context="\n".join(context_lines) if context_lines else None,
                                match=node
                            )
                            report.add_tool_usage(tool_usage)
            
            # Start scanning from the root
            scan_node(data)
            logger.debug("Completed YAML content scan")
            
    except Exception as e:
        logger.error(f"Error scanning YAML file {file_path}: {e}", exc_info=True)
        
    return report

def scan_file(file_path: str) -> SecurityReport:
    """
    Scan a file for potential security issues.
    
    Args:
        file_path: Path to the file
        
    Returns:
        SecurityReport containing findings
    """
    logger.debug(f"Starting file scan: {file_path}")
    file_path = str(file_path)
    if file_path.endswith('.py'):
        return scan_python_file(file_path)
    elif file_path.endswith(('.yaml', '.yml')):
        return scan_yaml_file(file_path)
    else:
        raise ValueError(f"Unsupported file type: {file_path}") 