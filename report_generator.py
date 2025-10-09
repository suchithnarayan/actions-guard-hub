#!/usr/bin/env python3
"""
Report Generator for GitHub Actions Security Scanner

This module generates human-readable text reports from scan results,
providing comprehensive summaries of security analysis for GitHub Actions.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class ScanReportGenerator:
    """
    Generates comprehensive text reports from GitHub Actions security scan results.
    
    Creates readable reports that include:
    - Action metadata and version information
    - Security analysis summary
    - Detailed findings and recommendations
    - Repository statistics
    - Scan metadata (tokens, cost, etc.)
    """
    
    def __init__(self, reports_dir: str = "scan-reports"):
        """
        Initialize the report generator.
        
        Args:
            reports_dir: Directory to store generated reports
        """
        self.reports_dir = reports_dir
        self.ensure_reports_directory()
    
    def ensure_reports_directory(self):
        """Create the reports directory if it doesn't exist."""
        os.makedirs(self.reports_dir, exist_ok=True)
        logger.info(f"Reports directory: {self.reports_dir}")
    
    def generate_single_action_report(self, 
                                    action_ref: str,
                                    scan_result_path: str,
                                    metadata_path: Optional[str] = None,
                                    action_stats: Optional[Dict] = None,
                                    commit_sha: Optional[str] = None) -> str:
        """
        Generate a report for a single GitHub action.
        
        Args:
            action_ref: GitHub action reference (e.g., "actions/checkout@v4")
            scan_result_path: Path to the JSON scan result file
            metadata_path: Optional path to metadata file
            action_stats: Optional action statistics from actions-stats.json
            
        Returns:
            Path to the generated report file
        """
        logger.info(f"Generating report for action: {action_ref}")
        
        # Load scan result
        scan_data = self._load_json_file(scan_result_path)
        if not scan_data:
            raise ValueError(f"Could not load scan result from {scan_result_path}")
        
        # Update commit SHA if provided (for existing scans)
        if commit_sha and scan_data.get('SHA') in ['N/A', None, '']:
            scan_data['SHA'] = commit_sha
            logger.debug(f"Updated commit SHA in scan data: {commit_sha[:8]}...")
        
        # Load metadata if available
        metadata = {}
        if metadata_path and os.path.exists(metadata_path):
            metadata = self._load_metadata_file(metadata_path)
        
        # Generate report content
        report_content = self._generate_report_content(action_ref, scan_data, metadata, action_stats)
        
        # Save report
        report_filename = self._get_report_filename(action_ref)
        report_path = os.path.join(self.reports_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"Report generated: {report_path}")
        return report_path
    
    def generate_batch_report(self, 
                            actions_data: List[Dict[str, Any]], 
                            report_name: str = "batch_scan_report") -> str:
        """
        Generate a batch report for multiple GitHub actions.
        
        Args:
            actions_data: List of dictionaries containing action data
            report_name: Name for the batch report
            
        Returns:
            Path to the generated batch report file
        """
        logger.info(f"Generating batch report for {len(actions_data)} actions")
        
        # Generate batch report content
        report_content = self._generate_batch_report_content(actions_data, report_name)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{report_name}_{timestamp}.txt"
        report_path = os.path.join(self.reports_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"Batch report generated: {report_path}")
        return report_path
    
    def _load_json_file(self, file_path: str) -> Optional[Dict]:
        """Load and parse a JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading JSON file {file_path}: {e}")
            return None
    
    def _load_metadata_file(self, file_path: str) -> Dict[str, str]:
        """Load metadata from a text file."""
        metadata = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                for line in content.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        metadata[key.strip()] = value.strip()
        except Exception as e:
            logger.error(f"Error loading metadata file {file_path}: {e}")
        return metadata
    
    def _get_report_filename(self, action_ref: str) -> str:
        """Generate a safe filename for the report."""
        # Replace special characters with safe alternatives
        safe_name = action_ref.replace('/', '-').replace('@', '_').replace(':', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{safe_name}_{timestamp}.txt"
    
    def _generate_report_content(self, 
                               action_ref: str, 
                               scan_data: Dict, 
                               metadata: Dict, 
                               action_stats: Optional[Dict]) -> str:
        """Generate the main report content."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("GITHUB ACTIONS SECURITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Basic Information
        lines.append("📋 BASIC INFORMATION")
        lines.append("-" * 40)
        lines.append(f"Action Reference: {action_ref}")
        lines.append(f"Action Name: {scan_data.get('action-name', 'Unknown')}")
        lines.append(f"Repository: {scan_data.get('repo-name', 'Unknown')}")
        lines.append(f"Version/Tag: {scan_data.get('version', 'Unknown')}")
        lines.append(f"Commit SHA: {scan_data.get('SHA', 'Unknown')}")
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Repository Statistics (if available)
        if action_stats and 'repository' in action_stats:
            repo_info = action_stats['repository']
            lines.append("📊 REPOSITORY STATISTICS")
            lines.append("-" * 40)
            lines.append(f"Created: {repo_info.get('created_at', 'Unknown')}")
            lines.append(f"Stars: {repo_info.get('stars', 'Unknown'):,}")
            lines.append(f"Contributors: {repo_info.get('contributors', 'Unknown'):,}")
            lines.append(f"Issues: {repo_info.get('issues', 'Unknown'):,}")
            lines.append("")
        
        # Security Analysis Summary
        lines.extend(self._generate_security_summary(scan_data))
        
        # Detailed Security Checks
        lines.extend(self._generate_detailed_checks(scan_data))
        
        # Security Issues
        lines.extend(self._generate_security_issues(scan_data))
        
        # Recommendations
        lines.extend(self._generate_recommendations(scan_data))
        
        # Mitigation Strategies
        lines.extend(self._generate_mitigation_strategies(scan_data))
        
        # Risk Assessment
        lines.extend(self._generate_risk_assessment(scan_data))
        
        # Scan Metadata
        if metadata:
            lines.extend(self._generate_scan_metadata(metadata))
        
        # Footer
        lines.append("")
        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def _generate_security_summary(self, scan_data: Dict) -> List[str]:
        """Generate security analysis summary."""
        lines = []
        lines.append("🔍 SECURITY ANALYSIS SUMMARY")
        lines.append("-" * 40)
        
        checks = scan_data.get('checks', [])
        if checks:
            safe_count = sum(1 for check in checks if check.get('status') == 'safe')
            unsafe_count = sum(1 for check in checks if check.get('status') == 'unsafe')
            total_checks = len(checks)
            
            lines.append(f"Total Security Checks: {total_checks}")
            lines.append(f"✅ Safe Checks: {safe_count}")
            lines.append(f"⚠️  Unsafe Checks: {unsafe_count}")
            lines.append(f"Safety Score: {safe_count}/{total_checks} ({(safe_count/total_checks*100):.1f}%)")
        
        # Count security issues by severity
        issues = scan_data.get('Security-Issues', [])
        if issues:
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for issue in issues:
                severity = issue.get('severity', 'Unknown')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            lines.append("")
            lines.append("Security Issues by Severity:")
            for severity, count in severity_counts.items():
                if count > 0:
                    emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
                    lines.append(f"  {emoji.get(severity, '⚪')} {severity}: {count}")
        
        lines.append("")
        return lines
    
    def _generate_detailed_checks(self, scan_data: Dict) -> List[str]:
        """Generate detailed security checks section."""
        lines = []
        lines.append("🔒 DETAILED SECURITY CHECKS")
        lines.append("-" * 40)
        
        checks = scan_data.get('checks', [])
        for check in checks:
            status_emoji = "✅" if check.get('status') == 'safe' else "⚠️"
            lines.append(f"{status_emoji} {check.get('title', 'Unknown Check')}")
            lines.append(f"   Status: {check.get('status', 'Unknown').upper()}")
            lines.append(f"   Score: {check.get('score', 'N/A')}")
            
            analysis = check.get('analysis', '')
            if analysis:
                # Wrap long analysis text
                wrapped_analysis = self._wrap_text(analysis, 70, "   ")
                lines.append(f"   Analysis: {wrapped_analysis}")
            
            lines.append("")
        
        return lines
    
    def _generate_security_issues(self, scan_data: Dict) -> List[str]:
        """Generate security issues section."""
        lines = []
        issues = scan_data.get('Security-Issues', [])
        
        if issues:
            lines.append("🚨 SECURITY ISSUES FOUND")
            lines.append("-" * 40)
            
            for i, issue in enumerate(issues, 1):
                severity = issue.get('severity', 'Unknown')
                severity_emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
                
                lines.append(f"{i}. {severity_emoji} {severity.upper()} SEVERITY")
                lines.append(f"   File: {issue.get('file', 'Unknown')}")
                lines.append(f"   Line: {issue.get('line', 'Unknown')}")
                
                description = issue.get('description', '')
                if description:
                    wrapped_desc = self._wrap_text(description, 70, "   ")
                    lines.append(f"   Description: {wrapped_desc}")
                
                lines.append("")
        else:
            lines.append("✅ NO SECURITY ISSUES FOUND")
            lines.append("-" * 40)
            lines.append("No security issues were identified during the scan.")
            lines.append("")
        
        return lines
    
    def _generate_recommendations(self, scan_data: Dict) -> List[str]:
        """Generate recommendations section."""
        lines = []
        lines.append("💡 RECOMMENDATIONS")
        lines.append("-" * 40)
        
        recommendations = scan_data.get('Recommendations', [])
        if recommendations:
            for rec in recommendations:
                if 'verdict' in rec:
                    verdict = rec['verdict']
                    verdict_emoji = "❌" if "malicious" in verdict.lower() else "✅"
                    lines.append(f"{verdict_emoji} Verdict: {verdict}")
                
                if 'description' in rec:
                    wrapped_desc = self._wrap_text(rec['description'], 70, "")
                    lines.append(f"Description: {wrapped_desc}")
                
                lines.append("")
        
        return lines
    
    def _generate_mitigation_strategies(self, scan_data: Dict) -> List[str]:
        """Generate mitigation strategies section."""
        lines = []
        mitigation = scan_data.get('mitigation-stratagy', [])  # Note: keeping original typo for compatibility
        
        if mitigation:
            lines.append("🛡️ MITIGATION STRATEGIES")
            lines.append("-" * 40)
            
            for i, strategy in enumerate(mitigation, 1):
                if isinstance(strategy, dict) and 'description' in strategy:
                    wrapped_desc = self._wrap_text(strategy['description'], 70, "")
                    lines.append(f"{i}. {wrapped_desc}")
                elif isinstance(strategy, str):
                    wrapped_desc = self._wrap_text(strategy, 70, "")
                    lines.append(f"{i}. {wrapped_desc}")
                lines.append("")
        
        return lines
    
    def _generate_risk_assessment(self, scan_data: Dict) -> List[str]:
        """Generate risk assessment section."""
        lines = []
        lines.append("⚖️ RISK ASSESSMENT")
        lines.append("-" * 40)
        
        risk_assessment = scan_data.get('risk-assessment', '')
        if risk_assessment:
            wrapped_risk = self._wrap_text(risk_assessment, 70, "")
            lines.append(wrapped_risk)
        else:
            lines.append("No risk assessment available.")
        
        lines.append("")
        return lines
    
    def _generate_scan_metadata(self, metadata: Dict) -> List[str]:
        """Generate scan metadata section."""
        lines = []
        lines.append("📈 SCAN METADATA")
        lines.append("-" * 40)
        
        for key, value in metadata.items():
            lines.append(f"{key}: {value}")
        
        lines.append("")
        return lines
    
    def _generate_batch_report_content(self, actions_data: List[Dict], report_name: str) -> str:
        """Generate batch report content."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("GITHUB ACTIONS BATCH SECURITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Report Name: {report_name}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Actions Scanned: {len(actions_data)}")
        lines.append("")
        
        # Summary Statistics
        lines.extend(self._generate_batch_summary(actions_data))
        
        # Individual Action Summaries
        lines.append("📋 INDIVIDUAL ACTION SUMMARIES")
        lines.append("-" * 80)
        lines.append("")
        
        for i, action_data in enumerate(actions_data, 1):
            action_ref = action_data.get('action_ref', f'Action {i}')
            scan_data = action_data.get('scan_data', {})
            
            lines.append(f"{i}. {action_ref}")
            lines.append("   " + "-" * 60)
            
            # Quick summary
            checks = scan_data.get('checks', [])
            if checks:
                safe_count = sum(1 for check in checks if check.get('status') == 'safe')
                total_checks = len(checks)
                lines.append(f"   Safety Score: {safe_count}/{total_checks} ({(safe_count/total_checks*100):.1f}%)")
            
            issues = scan_data.get('Security-Issues', [])
            if issues:
                lines.append(f"   Security Issues: {len(issues)}")
            else:
                lines.append("   Security Issues: None")
            
            # Verdict
            recommendations = scan_data.get('Recommendations', [])
            if recommendations and recommendations[0].get('verdict'):
                verdict = recommendations[0]['verdict']
                verdict_emoji = "❌" if "malicious" in verdict.lower() else "✅"
                lines.append(f"   Verdict: {verdict_emoji} {verdict}")
            
            lines.append("")
        
        # Footer
        lines.append("=" * 80)
        lines.append("End of Batch Report")
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def _generate_batch_summary(self, actions_data: List[Dict]) -> List[str]:
        """Generate summary statistics for batch report."""
        lines = []
        lines.append("📊 BATCH SUMMARY STATISTICS")
        lines.append("-" * 40)
        
        total_actions = len(actions_data)
        safe_actions = 0
        total_issues = 0
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for action_data in actions_data:
            scan_data = action_data.get('scan_data', {})
            
            # Count safe actions
            checks = scan_data.get('checks', [])
            if checks:
                safe_count = sum(1 for check in checks if check.get('status') == 'safe')
                if safe_count == len(checks):
                    safe_actions += 1
            
            # Count issues by severity
            issues = scan_data.get('Security-Issues', [])
            total_issues += len(issues)
            for issue in issues:
                severity = issue.get('severity', 'Unknown')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        lines.append(f"Total Actions: {total_actions}")
        lines.append(f"Fully Safe Actions: {safe_actions} ({(safe_actions/total_actions*100):.1f}%)")
        lines.append(f"Actions with Issues: {total_actions - safe_actions}")
        lines.append(f"Total Security Issues: {total_issues}")
        lines.append("")
        
        if total_issues > 0:
            lines.append("Issues by Severity:")
            for severity, count in severity_counts.items():
                if count > 0:
                    emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
                    lines.append(f"  {emoji.get(severity, '⚪')} {severity}: {count}")
        
        lines.append("")
        return lines
    
    def _wrap_text(self, text: str, width: int = 70, indent: str = "") -> str:
        """Wrap text to specified width with optional indentation."""
        if not text:
            return ""
        
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            if current_length + len(word) + 1 <= width:
                current_line.append(word)
                current_length += len(word) + 1
            else:
                if current_line:
                    lines.append(indent + ' '.join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            lines.append(indent + ' '.join(current_line))
        
        return '\n'.join(lines) if len(lines) > 1 else lines[0] if lines else ""


def create_report_from_existing_scan(action_ref: str, 
                                   scan_report_path: str, 
                                   action_stats: Optional[Dict] = None,
                                   reports_dir: str = "scan-reports") -> str:
    """
    Create a report from an existing scan result.
    
    Args:
        action_ref: GitHub action reference
        scan_report_path: Path to existing scan result JSON
        action_stats: Optional action statistics
        reports_dir: Directory for reports
        
    Returns:
        Path to generated report
    """
    generator = ScanReportGenerator(reports_dir)
    
    # Derive metadata path from scan report path
    metadata_path = scan_report_path.replace('.json', '-metadata.txt')
    if not os.path.exists(metadata_path):
        # Try alternative metadata path structure
        base_name = os.path.basename(scan_report_path).replace('.json', '')
        metadata_dir = os.path.join(os.path.dirname(scan_report_path), '..', 'output-metadata')
        metadata_path = os.path.join(metadata_dir, f"{base_name}-metadata.txt")
    
    return generator.generate_single_action_report(
        action_ref, 
        scan_report_path, 
        metadata_path if os.path.exists(metadata_path) else None,
        action_stats
    )
