#!/usr/bin/env python3
"""
Security Overview Generator

This module generates security overview data for the web dashboard,
aggregating scan results into a format suitable for visualization.

Author: GitHub Actions Security Scanner Team
License: MIT
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


def generate_security_overview(output_dir: str, overview_file: str, output_dir_fe: str) -> bool:
    """
    Generate security overview JSON file for the web dashboard.
    
    This function aggregates all scan results into a summary format that can be
    easily consumed by the frontend dashboard for visualization.
    
    Args:
        output_dir: Directory containing scan result JSON files
        overview_file: Name of the overview file to generate
        output_dir_fe: Frontend output directory name (for file paths)
        
    Returns:
        True if overview generated successfully, False otherwise
    """
    try:
        logger.info(f"🔄 Generating security overview from {output_dir}")
        
        output_path = Path(output_dir)
        if not output_path.exists():
            logger.warning(f"⚠️  Output directory does not exist: {output_dir}")
            return False
        
        # Get all JSON files except the overview file itself
        json_files = [
            f for f in output_path.iterdir() 
            if f.suffix == '.json' and f.name != overview_file
        ]
        
        if not json_files:
            logger.warning(f"⚠️  No scan result files found in {output_dir}")
            return False
        
        logger.info(f"📊 Processing {len(json_files)} scan result files")
        
        overview_data = []
        processed_count = 0
        error_count = 0
        
        for json_file in json_files:
            try:
                scan_data = _load_scan_result(json_file)
                if scan_data:
                    overview_item = _create_overview_item(scan_data, json_file.name, output_dir_fe)
                    if overview_item:
                        overview_data.append(overview_item)
                        processed_count += 1
                    else:
                        error_count += 1
                else:
                    error_count += 1
                    
            except Exception as e:
                logger.warning(f"⚠️  Error processing {json_file.name}: {e}")
                error_count += 1
        
        # Sort by action name for consistent ordering
        overview_data.sort(key=lambda x: x.get('actionName', '').lower())
        
        # Save overview file
        overview_path = output_path / overview_file
        with open(overview_path, 'w', encoding='utf-8') as f:
            json.dump(overview_data, f, indent=2)
        
        logger.info(
            f"✅ Security overview generated: {overview_path} "
            f"({processed_count} processed, {error_count} errors)"
        )
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to generate security overview: {e}")
        return False


def _load_scan_result(json_file: Path) -> Optional[Dict[str, Any]]:
    """
    Load and validate a scan result JSON file.
    
    Args:
        json_file: Path to the JSON file
        
    Returns:
        Parsed JSON data or None if failed
    """
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Basic validation
        if not isinstance(data, dict):
            logger.warning(f"⚠️  Invalid JSON structure in {json_file.name}")
            return None
        
        return data
        
    except json.JSONDecodeError as e:
        logger.warning(f"⚠️  Invalid JSON in {json_file.name}: {e}")
        return None
    except Exception as e:
        logger.warning(f"⚠️  Error reading {json_file.name}: {e}")
        return None


def _create_overview_item(scan_data: Dict[str, Any], filename: str, output_dir_fe: str) -> Optional[Dict[str, Any]]:
    """
    Create an overview item from scan data.
    
    Args:
        scan_data: Parsed scan result data
        filename: Name of the scan result file
        output_dir_fe: Frontend output directory name
        
    Returns:
        Overview item dictionary or None if failed
    """
    try:
        # Extract basic information
        action_name = scan_data.get("action-name", _extract_action_name_from_filename(filename))
        repo_name = scan_data.get("repo-name", "Unknown Repository")
        sha = scan_data.get("SHA", _extract_sha_from_filename(filename))
        
        # Count security checks
        checks = scan_data.get("checks", [])
        safe_checks = sum(1 for check in checks if check.get("status", "").lower() == "safe")
        unsafe_checks = sum(1 for check in checks if check.get("status", "").lower() == "unsafe")
        
        # Count security issues by severity
        security_issues = scan_data.get("Security-Issues", scan_data.get("issues", []))
        severity_counts = _count_issues_by_severity(security_issues)
        
        # Create overview item
        overview_item = {
            "actionName": action_name,
            "repoName": repo_name,
            "sha": _format_sha(sha),
            "safeChecks": safe_checks,
            "unsafeChecks": unsafe_checks,
            "criticalIssues": severity_counts["critical"],
            "highIssues": severity_counts["high"],
            "mediumIssues": severity_counts["medium"],
            "lowIssues": severity_counts["low"],
            "file": f"{output_dir_fe}/{filename}",
        }
        
        return overview_item
        
    except Exception as e:
        logger.warning(f"⚠️  Error creating overview item for {filename}: {e}")
        return None


def _extract_action_name_from_filename(filename: str) -> str:
    """
    Extract action name from filename.
    
    Args:
        filename: Name of the scan result file
        
    Returns:
        Extracted action name
    """
    try:
        # Remove .json extension and convert dashes to slashes
        base_name = filename.replace('.json', '')
        
        # Handle different filename formats
        if '-' in base_name:
            # Convert first dash to slash for owner/repo format
            parts = base_name.split('-', 1)
            if len(parts) == 2:
                return f"{parts[0]}/{parts[1]}"
        
        return base_name
        
    except Exception:
        return "Unknown Action"


def _extract_sha_from_filename(filename: str) -> str:
    """
    Extract SHA from filename if present.
    
    Args:
        filename: Name of the scan result file
        
    Returns:
        Extracted SHA or "Unknown"
    """
    try:
        # Look for SHA-like patterns in filename
        parts = filename.replace('.json', '').split('-')
        
        for part in parts:
            # Check if part looks like a SHA (7+ hex characters)
            if len(part) >= 7 and all(c in '0123456789abcdef' for c in part.lower()):
                return part
        
        return "Unknown"
        
    except Exception:
        return "Unknown"


def _format_sha(sha: str) -> str:
    """
    Format SHA for display (truncate to 7 characters).
    
    Args:
        sha: Full SHA string
        
    Returns:
        Formatted SHA string
    """
    if isinstance(sha, str) and len(sha) >= 7:
        return sha[:7]
    return "Unknown"


def _count_issues_by_severity(security_issues: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count security issues by severity level.
    
    Args:
        security_issues: List of security issue dictionaries
        
    Returns:
        Dictionary with counts for each severity level
    """
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    
    for issue in security_issues:
        if isinstance(issue, dict):
            severity = issue.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    return severity_counts


def validate_overview_data(overview_data: List[Dict[str, Any]]) -> bool:
    """
    Validate the structure of overview data.
    
    Args:
        overview_data: List of overview items
        
    Returns:
        True if data is valid, False otherwise
    """
    required_fields = {
        "actionName", "repoName", "sha", "safeChecks", "unsafeChecks",
        "criticalIssues", "highIssues", "mediumIssues", "lowIssues", "file"
    }
    
    try:
        if not isinstance(overview_data, list):
            return False
        
        for item in overview_data:
            if not isinstance(item, dict):
                return False
            
            # Check required fields
            if not all(field in item for field in required_fields):
                return False
            
            # Check data types
            numeric_fields = {
                "safeChecks", "unsafeChecks", "criticalIssues", 
                "highIssues", "mediumIssues", "lowIssues"
            }
            
            for field in numeric_fields:
                if not isinstance(item[field], int) or item[field] < 0:
                    return False
        
        return True
        
    except Exception:
        return False


def get_overview_statistics(overview_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate aggregate statistics from overview data.
    
    Args:
        overview_data: List of overview items
        
    Returns:
        Dictionary with aggregate statistics
    """
    if not overview_data:
        return {
            "total_actions": 0,
            "total_safe_checks": 0,
            "total_unsafe_checks": 0,
            "total_issues": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "safety_percentage": 0.0
        }
    
    total_actions = len(overview_data)
    total_safe_checks = sum(item["safeChecks"] for item in overview_data)
    total_unsafe_checks = sum(item["unsafeChecks"] for item in overview_data)
    
    severity_breakdown = {
        "critical": sum(item["criticalIssues"] for item in overview_data),
        "high": sum(item["highIssues"] for item in overview_data),
        "medium": sum(item["mediumIssues"] for item in overview_data),
        "low": sum(item["lowIssues"] for item in overview_data),
    }
    
    total_issues = sum(severity_breakdown.values())
    total_checks = total_safe_checks + total_unsafe_checks
    safety_percentage = (total_safe_checks / total_checks * 100) if total_checks > 0 else 0.0
    
    return {
        "total_actions": total_actions,
        "total_safe_checks": total_safe_checks,
        "total_unsafe_checks": total_unsafe_checks,
        "total_issues": total_issues,
        "severity_breakdown": severity_breakdown,
        "safety_percentage": round(safety_percentage, 1)
    }
