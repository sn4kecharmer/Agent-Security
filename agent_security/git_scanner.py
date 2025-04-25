"""
Git repository scanner for agent configurations.
"""

import os
import tempfile
import shutil
from typing import List, Optional
from pathlib import Path
import git
from .models import SecurityReport
from .file_scanner import scan_file

class GitScanner:
    """Scans agent configurations in a Git repository."""
    
    def __init__(self, repo_url: str, branch: Optional[str] = None):
        """
        Initialize the Git scanner.
        
        Args:
            repo_url: URL of the Git repository
            branch: Optional branch name to scan (defaults to main/master)
        """
        self.repo_url = repo_url
        self.branch = branch
        self.temp_dir = None
        self.repo = None

    def __enter__(self):
        """Set up the temporary directory and clone the repository."""
        self.temp_dir = tempfile.mkdtemp()
        try:
            self.repo = git.Repo.clone_from(
                self.repo_url,
                self.temp_dir,
                branch=self.branch if self.branch else None
            )
        except git.exc.GitCommandError as e:
            raise ValueError(f"Failed to clone repository: {e}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up the temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

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
            config_files.extend(Path(self.temp_dir).rglob(pattern))
        
        return config_files

    def scan_repository(self) -> List[SecurityReport]:
        """
        Scan all configuration files in the repository.
        
        Returns:
            List of security reports for each configuration file
        """
        if not self.repo:
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
            "commit_hash": self.repo.head.commit.hexsha if self.repo else None
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