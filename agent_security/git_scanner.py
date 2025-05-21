"""
Git repository scanning functionality.
"""

import os
import tempfile
import logging
from pathlib import Path
from typing import List, Optional
from .models import SecurityReport
from .file_scanner import scan_file
import re

logger = logging.getLogger(__name__)

def sanitize_git_error(error: Exception) -> str:
    """Sanitize Git error messages to remove sensitive information."""
    error_str = str(error)
    # Remove potential tokens from URLs
    error_str = re.sub(r'(https?://[^:]+:)[^@]+@', r'\1***@', error_str)
    # Remove potential paths
    error_str = re.sub(r'/[^\s]+', '***', error_str)
    return error_str

class GitScanner:
    """Scanner for Git repositories."""
    
    def __init__(self, repo_url: str, branch: Optional[str] = None):
        self.repo_url = repo_url
        self.branch = branch
        self._temp_dir = None
        self._repo = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        """Clean up temporary files."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            import shutil
            shutil.rmtree(self._temp_dir)

    def clone_repository(self):
        """Clone the repository to a temporary directory."""
        try:
            import git
        except ImportError:
            raise ValueError("Git support is not available. Please install git to use this feature.")

        self._temp_dir = tempfile.mkdtemp()
        try:
            self._repo = git.Repo.clone_from(self.repo_url, self._temp_dir)
            if self.branch:
                self._repo.git.checkout(self.branch)
        except Exception as e:
            self.cleanup()
            raise ValueError(f"Failed to clone repository: {e}")

    def scan(self) -> SecurityReport:
        """
        Scan the repository for security issues.
        
        Returns:
            SecurityReport containing findings
        """
        try:
            self.clone_repository()
            # Scan all Python and YAML files in the repository
            report = SecurityReport()
            for ext in ['*.py', '*.yaml', '*.yml']:
                for file_path in Path(self._temp_dir).rglob(ext):
                    if '.git' in file_path.parts:
                        continue
                    try:
                        file_report = scan_file(str(file_path))
                        if file_report and file_report.findings:
                            report.merge(file_report)
                    except Exception as e:
                        logger.error(f"Error scanning file {file_path}: {e}")
            return report
        finally:
            self.cleanup()

    def find_config_files(self) -> List[Path]:
        """
        Find all potential agent configuration files in the repository.
        
        Returns:
            List of paths to configuration files
        """
        config_files = []
        
        # Common configuration file patterns
        config_patterns = [
            "*.yaml",
            "*.yml",
            "*.py",
            "agent_config*",
            "config/agent*",
            "agents/*.yaml",
            "agents/*.yml",
            "agents/*.py"
        ]
        
        for pattern in config_patterns:
            config_files.extend(Path(self._temp_dir).rglob(pattern))
        
        return config_files

    def scan_repository(self) -> List[SecurityReport]:
        """
        Scan all configuration files in the repository.
        
        Returns:
            List of security reports for each configuration file
        """
        if not self._repo:
            raise ValueError("Repository not initialized. Use with context manager.")
        
        reports = []
        config_files = self.find_config_files()
        
        for config_file in config_files:
            try:
                report = scan_file(str(config_file))
                reports.append(report)
            except Exception as e:
                print(f"Error scanning {config_file}: {e}")
        
        return reports

    def get_summary(self, reports: List[SecurityReport]) -> dict:
        """
        Generate a summary of security findings across all reports.
        
        Args:
            reports: List of security reports
            
        Returns:
            Dictionary containing summary information
        """
        summary = {
            "total_files_scanned": len(reports),
            "high_risk_files": 0,
            "medium_risk_files": 0,
            "low_risk_files": 0,
            "files_by_risk": {},
            "common_issues": {},
            "repository_url": self.repo_url,
            "branch": self.branch or "default",
            "commit_hash": self._repo.head.commit.hexsha if self._repo else None
        }
        
        # Count files by risk level
        for report in reports:
            risk_level = report.overall_risk.name if report.overall_risk else "LOW"
            summary["files_by_risk"][risk_level] = summary["files_by_risk"].get(risk_level, 0) + 1
            
            if risk_level == "HIGH":
                summary["high_risk_files"] += 1
            elif risk_level == "MEDIUM":
                summary["medium_risk_files"] += 1
            else:
                summary["low_risk_files"] += 1
            
            # Track common issues
            for tool in report.tool_usages:
                issue = f"{tool.name} ({tool.risk_level.name})"
                summary["common_issues"][issue] = summary["common_issues"].get(issue, 0) + 1
            
            for tool in report.obfuscated_usages:
                issue = f"Obfuscated: {tool.name} ({tool.risk_level.name})"
                summary["common_issues"][issue] = summary["common_issues"].get(issue, 0) + 1
            
            for tool in report.tool_combinations:
                issue = f"Combination: {tool.name} ({tool.risk_level.name})"
                summary["common_issues"][issue] = summary["common_issues"].get(issue, 0) + 1
            
            for tool in report.security_rules:
                issue = f"Rule: {tool.name} ({tool.risk_level.name})"
                summary["common_issues"][issue] = summary["common_issues"].get(issue, 0) + 1
        
        # Sort common issues by frequency
        summary["common_issues"] = dict(
            sorted(
                summary["common_issues"].items(),
                key=lambda x: x[1],
                reverse=True
            )
        )
        
        return summary 