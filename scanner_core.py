#!/usr/bin/env python3
"""
GitHub Actions Scanner Core (Refactored)

This module contains the refactored core scanning logic for GitHub Actions security analysis.
It orchestrates the scanning workflow using modular components for better maintainability.

Author: GitHub Actions Security Scanner Team
License: MIT
"""

import os
import json
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from github_auth import GitHubAuthManager
from github_client import GitHubClient
from ai_core import AICore, create_ai_core
from file_processor import FileProcessor, create_file_processor
from report_generator import ScanReportGenerator

logger = logging.getLogger(__name__)


class GitHubActionsScanner:
    """
    Refactored core scanner class for GitHub Actions security analysis.
    
    This class orchestrates the complete scanning workflow using modular components:
    - GitHubClient: Handles all GitHub API interactions
    - AICore: Manages AI model interactions for security analysis
    - FileProcessor: Handles file extraction and processing
    - ScanReportGenerator: Generates human-readable reports
    """
    
    def __init__(self, config: Dict, auth_manager: GitHubAuthManager):
        """
        Initialize the scanner with configuration and authentication.
        
        Args:
            config: Scanner configuration dictionary
            auth_manager: Initialized GitHub authentication manager
        """
        self.config = config
        self.auth_manager = auth_manager
        self.existing_metadata = {}
        self.security_prompt = None
        
        # Initialize modular components
        self.github_client = GitHubClient(auth_manager)
        
        # Initialize AI core with configuration
        ai_model = config.get('ai_model', 'gemini')
        model_name = config.get('model_name')
        self.ai_core = create_ai_core(ai_model, model_name)
        
        self.file_processor = create_file_processor()
        self.report_generator = ScanReportGenerator(config['reports_dir'])
        
        # Track generated reports
        self.generated_reports = []
        
        logger.debug("🔧 Refactored scanner core initialized")
    
    def load_existing_metadata(self, stats_file: str) -> bool:
        """
        Load existing action metadata and statistics.
        
        Args:
            stats_file: Path to the statistics JSON file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            with open(stats_file, 'r', encoding='utf-8') as f:
                self.existing_metadata = json.load(f)
            
            repo_count = len(self.existing_metadata)
            logger.info(f"📊 Loaded metadata for {repo_count} repositories")
            return True
            
        except Exception as e:
            logger.warning(f"⚠️  Could not load existing metadata: {e}")
            self.existing_metadata = {}
            return False
    
    def load_prompt(self, prompt_file: str) -> bool:
        """
        Load the security analysis prompt from file.
        
        Args:
            prompt_file: Path to the prompt file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                self.security_prompt = f.read().strip()
            
            if not self.security_prompt:
                logger.error("❌ Security prompt is empty")
                return False
            
            logger.debug(f"📝 Loaded security prompt ({len(self.security_prompt)} characters)")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to load prompt from {prompt_file}: {e}")
            return False
    
    def scan_action(self, action_ref: str, skip_ai_scan: bool = False) -> Dict[str, Any]:
        """
        Perform complete security scan of a GitHub action.
        
        Args:
            action_ref: GitHub action reference (e.g., "actions/checkout@v4")
            skip_ai_scan: Whether to skip AI analysis
            
        Returns:
            Dictionary containing scan results and metadata
        """
        result = {
            'success': False,
            'action_ref': action_ref,
            'scan_type': 'new',
            'report_path': None,
            'error': None
        }
        
        try:
            # Parse action reference
            owner, repo, version = self.github_client.parse_action_reference(action_ref)
            if not owner or not repo:
                result['error'] = f"Invalid action reference format: {action_ref}"
                return result
            
            owner_repo = f"{owner}/{repo}"
            logger.info(f"🎯 Processing: {owner_repo} @ {version}")
            
            # Update repository metadata
            self._update_repository_metadata(owner_repo, force_update=True)
            
            # Resolve version to actual release/tag or default branch
            resolved_version, commit_sha = self.github_client.resolve_version_and_sha(
                owner, repo, version, self.existing_metadata
            )
            logger.info(f"📌 Resolved version: {resolved_version} (SHA: {commit_sha[:8] if commit_sha else 'N/A'}...)")
            
            # Check if already scanned with valid report using resolved version
            scan_info = self._check_existing_scan(owner_repo, resolved_version)
            
            if scan_info['skip_scan']:
                logger.info(f"✅ Using existing scan results for {resolved_version}")
                result['scan_type'] = 'existing'
                result['report_path'] = self._generate_report_from_existing(
                    action_ref, scan_info['scan_path'], resolved_version, scan_info['commit_sha']
                )
                result['success'] = True
                return result
            
            # Skip AI scan if requested (metadata only)
            if skip_ai_scan:
                logger.info("⏭️  Skipping AI analysis (metadata only mode)")
                result['success'] = True
                return result
            
            # Perform fresh scan with resolved version
            resolved_action_ref = f"{owner_repo}@{resolved_version}"
            scan_result = self._perform_fresh_scan(resolved_action_ref, owner, repo, resolved_version, commit_sha)
            
            if scan_result['success']:
                result.update(scan_result)
                result['commit_sha'] = commit_sha
                
                # Update metadata with scan results
                self._update_scan_metadata(owner_repo, resolved_version, scan_result)
                
                # Save updated metadata
                self._save_metadata()
            else:
                result['error'] = scan_result.get('error', 'Unknown scan error')
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error scanning {action_ref}: {e}")
            result['error'] = str(e)
            return result
    
    def _update_repository_metadata(self, owner_repo: str, force_update: bool = False):
        """
        Update repository metadata using GitHub client.
        
        Args:
            owner_repo: Repository in owner/repo format
            force_update: If True, bypass timestamp caching and force update
        """
        try:
            # Check if we need to update metadata (unless forced)
            if not force_update and self._should_skip_metadata_update(owner_repo):
                logger.debug(f"⏭️  Skipping metadata update for {owner_repo} (recently updated)")
                return
            
            owner, repo = owner_repo.split('/')
            
            logger.info(f"🔄 Updating repository metadata: {owner_repo}")
            
            # Get repository statistics using GitHub client
            repo_stats = self.github_client.get_repository_stats(owner, repo)
            
            if repo_stats:
                if owner_repo not in self.existing_metadata:
                    logger.info(f"📝 Adding new repository: {owner_repo}")
                    self.existing_metadata[owner_repo] = repo_stats
                else:
                    logger.info(f"🔄 Merging repository metadata: {owner_repo}")
                    # Preserve existing releases data and merge intelligently
                    self._merge_repository_metadata(owner_repo, repo_stats)
                
                # Save metadata after update
                self._save_metadata()
                logger.info(f"✅ Metadata updated for {owner_repo}")
            else:
                logger.warning(f"⚠️  No metadata collected for {owner_repo}")
            
        except Exception as e:
            logger.error(f"❌ Failed to update metadata for {owner_repo}: {e}")
    
    def _should_skip_metadata_update(self, owner_repo: str) -> bool:
        """
        Check if metadata update should be skipped based on last update timestamp.
        
        Args:
            owner_repo: Repository in owner/repo format
            
        Returns:
            True if update should be skipped, False otherwise
        """
        if owner_repo not in self.existing_metadata:
            return False
        
        last_updated = self.existing_metadata[owner_repo].get('last_updated')
        if not last_updated:
            return False
        
        try:
            from datetime import datetime, timedelta
            last_update_time = datetime.fromisoformat(last_updated)
            time_diff = datetime.now() - last_update_time
            
            # Skip if updated within the last 6 hours
            cache_hours = 6
            if time_diff < timedelta(hours=cache_hours):
                logger.debug(f"Metadata for {owner_repo} updated {time_diff} ago, skipping (cache: {cache_hours}h)")
                return True
            else:
                logger.debug(f"Metadata for {owner_repo} updated {time_diff} ago, will update")
                return False
                
        except Exception as e:
            logger.debug(f"Error parsing last_updated timestamp for {owner_repo}: {e}")
            return False
    
    def _merge_repository_metadata(self, owner_repo: str, new_stats: Dict):
        """
        Intelligently merge new repository metadata with existing data.
        
        Args:
            owner_repo: Repository in owner/repo format
            new_stats: New statistics to merge
        """
        existing = self.existing_metadata[owner_repo]
        
        # Update repository info (stars, issues, contributors, etc.)
        if 'repository' in new_stats:
            old_repo = existing.get('repository', {})
            new_repo = new_stats['repository']
            
            # Log changes
            if old_repo.get('stars') != new_repo.get('stars'):
                logger.info(f"  📊 Stars: {old_repo.get('stars', 0)} → {new_repo.get('stars', 0)}")
            if old_repo.get('contributors') != new_repo.get('contributors'):
                logger.info(f"  👥 Contributors: {old_repo.get('contributors', 0)} → {new_repo.get('contributors', 0)}")
            if old_repo.get('issues') != new_repo.get('issues'):
                logger.info(f"  🐛 Issues: {old_repo.get('issues', 0)} → {new_repo.get('issues', 0)}")
            
            existing['repository'] = new_stats['repository']
        
        # Update last_updated timestamp
        existing['last_updated'] = new_stats.get('last_updated', datetime.now().isoformat())
        
        # Merge releases data intelligently
        if 'releases' in new_stats and new_stats['releases']:
            existing_releases = existing.get('releases', {})
            new_releases = new_stats['releases']
            
            releases_added = 0
            releases_updated = 0
            
            # For each new release, preserve existing scan data if available
            for release_name, release_data in new_releases.items():
                if release_name in existing_releases:
                    # Preserve existing scan data
                    existing_release = existing_releases[release_name]
                    
                    # Check if commit SHA changed
                    old_sha = existing_release.get('latest')
                    new_sha = release_data.get('latest')
                    if old_sha != new_sha:
                        logger.info(f"  🔄 {release_name}: SHA updated {old_sha[:8] if old_sha else 'None'} → {new_sha[:8] if new_sha else 'None'}")
                        releases_updated += 1
                        # If SHA changed, reset scan status
                        release_data['scanned'] = False
                        release_data['scan_report'] = None
                        release_data['safe'] = True
                    else:
                        # Preserve existing scan data
                        release_data['scanned'] = existing_release.get('scanned', False)
                        release_data['scan_report'] = existing_release.get('scan_report')
                        release_data['safe'] = existing_release.get('safe', True)
                    
                    # Preserve additional SHA data if available
                    if 'sha' in existing_release and len(existing_release['sha']) > 1:
                        # Merge SHA lists, keeping unique values
                        existing_shas = set(existing_release['sha'])
                        new_shas = set(release_data.get('sha', []))
                        release_data['sha'] = list(existing_shas.union(new_shas))
                else:
                    # New release found
                    logger.info(f"  ✨ New release found: {release_name}")
                    releases_added += 1
                
                existing_releases[release_name] = release_data
            
            existing['releases'] = existing_releases
            
            # Log summary
            total_releases = len(existing_releases)
            logger.info(f"  📦 Releases: {total_releases} total (+{releases_added} new, ~{releases_updated} updated)")
    
    def _check_existing_scan(self, owner_repo: str, version: str) -> Dict[str, Any]:
        """
        Check if action version has already been scanned with valid report.
        
        Args:
            owner_repo: Repository in owner/repo format
            version: Version or tag to check (should be resolved version)
            
        Returns:
            Dictionary with scan status information
        """
        result = {
            'skip_scan': False,
            'scan_path': None,
            'commit_sha': None,
            'version': version
        }
        
        try:
            if owner_repo not in self.existing_metadata:
                return result
            
            releases = self.existing_metadata[owner_repo].get("releases", {})
            
            # Check direct version match
            if version in releases:
                release_info = releases[version]
                result['commit_sha'] = release_info.get("latest")
                result['version'] = version
                
                if self._validate_existing_scan(release_info):
                    result['skip_scan'] = True
                    result['scan_path'] = self._resolve_scan_path(release_info["scan_report"])
                    return result
            
            # Check if version is a commit SHA
            for release_name, release_info in releases.items():
                for sha in release_info.get("sha", []):
                    if version == sha or sha.startswith(version):
                        result['commit_sha'] = sha
                        result['version'] = release_name
                        
                        if self._validate_existing_scan(release_info):
                            result['skip_scan'] = True
                            result['scan_path'] = self._resolve_scan_path(release_info["scan_report"])
                            return result
            
            return result
            
        except Exception as e:
            logger.warning(f"⚠️  Error checking existing scan for {owner_repo}@{version}: {e}")
            return result
    
    def _validate_existing_scan(self, release_info: Dict) -> bool:
        """
        Validate that an existing scan has both flag and valid file.
        
        Args:
            release_info: Release information dictionary
            
        Returns:
            True if scan is valid, False otherwise
        """
        if not release_info.get("scanned", False):
            return False
        
        scan_report_path = release_info.get("scan_report")
        if not scan_report_path:
            return False
        
        full_path = self._resolve_scan_path(scan_report_path)
        if not full_path or not Path(full_path).exists():
            logger.warning(f"⚠️  Scan report file missing: {scan_report_path}")
            # Reset scan status since file is missing
            release_info["scanned"] = False
            release_info["scan_report"] = None
            return False
        
        return True
    
    def _resolve_scan_path(self, scan_report_path: str) -> Optional[str]:
        """
        Resolve the full path for a scan report file.
        
        Args:
            scan_report_path: Relative or absolute path to scan report
            
        Returns:
            Absolute path to scan report, or None if not found
        """
        if not scan_report_path:
            return None
        
        # If already absolute, return as-is
        if Path(scan_report_path).is_absolute():
            return scan_report_path if Path(scan_report_path).exists() else None
        
        # Try different possible locations
        possible_paths = [
            Path(scan_report_path),
            Path("frontend") / scan_report_path,
            Path(self.config['output_dir']) / Path(scan_report_path).name,
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path.absolute())
        
        return None
    
    def _perform_fresh_scan(self, action_ref: str, owner: str, repo: str, version: str, commit_sha: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform a fresh security scan of the action using modular components.
        
        Args:
            action_ref: Full action reference
            owner: Repository owner
            repo: Repository name
            version: Version or tag
            
        Returns:
            Dictionary containing scan results
        """
        result = {
            'success': False,
            'scan_path': None,
            'report_path': None,
            'commit_sha': None,
            'tokens_used': 0,
            'cost': 0.0
        }
        
        action_dir = None
        
        try:
            logger.info(f"🔍 Performing fresh security scan...")
            
            # Download action using GitHub client
            action_dir = self.github_client.download_action(owner, repo, version)
            if not action_dir:
                result['error'] = "Failed to download action"
                return result
            
            # Extract relevant files using file processor
            action_files = self.file_processor.extract_action_files(action_dir)
            if not action_files:
                result['error'] = "No analyzable files found"
                return result
            
            logger.info(f"📁 Extracted {len(action_files)} files for analysis")
            
            # Validate extracted files
            validation = self.file_processor.validate_extracted_files(action_files)
            if not validation['valid']:
                result['error'] = f"File validation failed: {validation['errors']}"
                return result
            
            # Prepare files for AI analysis
            prepared_files = self.file_processor.prepare_for_analysis(action_files)
            
            # Perform AI security analysis
            analysis_result = self.ai_core.analyze_security(self.security_prompt, prepared_files)
            if not analysis_result['success']:
                result['error'] = analysis_result.get('error', 'AI analysis failed')
                return result
            
            # Save scan results
            scan_path = self._save_scan_results(
                action_ref, 
                analysis_result['content'],
                analysis_result['tokens_used'],
                analysis_result['cost'],
                version,
                commit_sha
            )
            
            if not scan_path:
                result['error'] = "Failed to save scan results"
                return result
            
            # Generate readable report
            report_path = self._generate_report_from_scan(
                action_ref, scan_path, version, result.get('commit_sha', '')
            )
            
            result.update({
                'success': True,
                'scan_path': scan_path,
                'report_path': report_path,
                'tokens_used': analysis_result['tokens_used'],
                'cost': analysis_result['cost']
            })
            
            logger.info(f"✅ Fresh scan completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"❌ Fresh scan failed: {e}")
            result['error'] = str(e)
            return result
            
        finally:
            # Cleanup temporary directory
            if action_dir and Path(action_dir).exists():
                # Get parent temp directory for cleanup
                temp_dir = Path(action_dir).parent
                if temp_dir.name.startswith("gha_scan_"):
                    shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _save_scan_results(self, action_ref: str, content: str, tokens_used: int, 
                          cost: float, version: str, commit_sha: Optional[str] = None) -> Optional[str]:
        """
        Save scan results to JSON file and metadata.
        
        Args:
            action_ref: Action reference string
            content: Analysis content from AI
            tokens_used: Number of tokens used
            cost: Cost of analysis
            version: Action version
            
        Returns:
            Path to saved scan file or None if failed
        """
        try:
            # Generate safe filename
            safe_name = action_ref.replace('/', '-').replace('@', '_').replace(':', '_')
            
            # Validate and fix JSON content using AI core
            logger.info("🔍 Validating and repairing JSON content...")
            validated_content = self.ai_core.validate_and_repair_json(content)
            
            # Parse JSON and add metadata
            try:
                json_content = json.loads(validated_content)
                
                # Add additional metadata fields to the JSON
                json_content.update({
                    "repo-name": action_ref,
                    "version": version,
                    "SHA": commit_sha if commit_sha else "N/A"
                })
                
                logger.info("✅ JSON content validated and metadata added")
                
            except json.JSONDecodeError as e:
                logger.warning(f"⚠️  Content is still not valid JSON after repair attempts: {str(e)[:100]}...")
                logger.info("📝 Saving as structured text with metadata wrapper")
                
                # Create a structured wrapper for non-JSON content
                json_content = {
                    "repo-name": action_ref,
                    "version": version,
                    "SHA": commit_sha if commit_sha else "N/A",
                    "scan_status": "completed_with_text_output",
                    "content_type": "text",
                    "raw_content": validated_content,
                    "note": "AI response could not be parsed as JSON, saved as raw text"
                }
            
            # Save JSON file with proper formatting
            output_file = Path(self.config['output_dir']) / f"{safe_name}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(json_content, f, indent=4, ensure_ascii=False)
            
            # Log the type of content saved
            if "raw_content" in json_content:
                logger.info(f"📝 Saved as structured text: {output_file}")
            else:
                logger.info(f"📊 Saved as valid JSON: {output_file}")
            
            # Save metadata file
            metadata_file = Path(self.config['metadata_dir']) / f"{safe_name}-metadata.txt"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                f.write(f"GitHub URL: {action_ref}\n")
                f.write(f"Total tokens used: {tokens_used}\n")
                f.write(f"Cost of operation: ${cost:.4f}\n")
                f.write(f"Scan timestamp: {datetime.now().isoformat()}\n")
            
            logger.info(f"💾 Scan results saved: {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"❌ Failed to save scan results: {e}")
            return None
    
    def _generate_report_from_existing(self, action_ref: str, scan_path: str, 
                                     version: str, commit_sha: str) -> Optional[str]:
        """
        Generate readable report from existing scan results.
        
        Args:
            action_ref: Action reference string
            scan_path: Path to existing scan JSON file
            version: Action version
            commit_sha: Commit SHA
            
        Returns:
            Path to generated report or None if failed
        """
        try:
            owner, repo, _ = self.github_client.parse_action_reference(action_ref)
            owner_repo = f"{owner}/{repo}"
            action_stats = self.existing_metadata.get(owner_repo, {})
            
            report_path = self.report_generator.generate_single_action_report(
                action_ref, scan_path, None, action_stats, commit_sha
            )
            
            self.generated_reports.append({
                'action_ref': action_ref,
                'report_path': report_path,
                'scan_result_path': scan_path,
                'version': version,
                'commit_sha': commit_sha
            })
            
            return report_path
            
        except Exception as e:
            logger.error(f"❌ Failed to generate report from existing scan: {e}")
            return None
    
    def _generate_report_from_scan(self, action_ref: str, scan_path: str, 
                                 version: str, commit_sha: str) -> Optional[str]:
        """
        Generate readable report from fresh scan results.
        
        Args:
            action_ref: Action reference string
            scan_path: Path to scan JSON file
            version: Action version
            commit_sha: Commit SHA
            
        Returns:
            Path to generated report or None if failed
        """
        try:
            owner, repo, _ = self.github_client.parse_action_reference(action_ref)
            owner_repo = f"{owner}/{repo}"
            action_stats = self.existing_metadata.get(owner_repo, {})
            
            # Generate metadata path
            base_name = Path(scan_path).stem
            metadata_path = Path(self.config['metadata_dir']) / f"{base_name}-metadata.txt"
            
            report_path = self.report_generator.generate_single_action_report(
                action_ref,
                scan_path,
                str(metadata_path) if metadata_path.exists() else None,
                action_stats,
                commit_sha
            )
            
            self.generated_reports.append({
                'action_ref': action_ref,
                'report_path': report_path,
                'scan_result_path': scan_path,
                'version': version,
                'commit_sha': commit_sha
            })
            
            return report_path
            
        except Exception as e:
            logger.error(f"❌ Failed to generate report from scan: {e}")
            return None
    
    def _update_scan_metadata(self, owner_repo: str, version: str, scan_result: Dict):
        """
        Update metadata with scan results.
        
        Args:
            owner_repo: Repository in owner/repo format
            version: Action version
            scan_result: Scan result dictionary
        """
        try:
            if owner_repo not in self.existing_metadata:
                self.existing_metadata[owner_repo] = {'releases': {}}
            
            if 'releases' not in self.existing_metadata[owner_repo]:
                self.existing_metadata[owner_repo]['releases'] = {}
            
            releases = self.existing_metadata[owner_repo]['releases']
            
            if version not in releases:
                releases[version] = {
                    'published_date': 'N/A',
                    'scanned': False,
                    'latest': scan_result.get('commit_sha', 'N/A'),
                    'sha': [scan_result.get('commit_sha', 'N/A')],
                    'safe': True,
                    'scan_report': None
                }
            
            # Update scan status
            releases[version].update({
                'scanned': True,
                'scan_report': scan_result.get('scan_path')
            })
            
        except Exception as e:
            logger.error(f"❌ Failed to update scan metadata: {e}")
    
    def _save_metadata(self):
        """Save updated metadata to file."""
        try:
            with open(self.config['stats_file'], 'w', encoding='utf-8') as f:
                json.dump(self.existing_metadata, f, indent=4)
            logger.debug("💾 Metadata saved successfully")
        except Exception as e:
            logger.error(f"❌ Failed to save metadata: {e}")
    
    def force_metadata_update(self, owner_repo: str) -> bool:
        """
        Force a metadata update for a repository, bypassing cache.
        
        Args:
            owner_repo: Repository in owner/repo format
            
        Returns:
            True if update successful, False otherwise
        """
        logger.info(f"🔄 Forcing metadata update for {owner_repo}")
        try:
            self._update_repository_metadata(owner_repo, force_update=True)
            return True
        except Exception as e:
            logger.error(f"❌ Failed to force update metadata for {owner_repo}: {e}")
            return False
    
    def generate_batch_summary_report(self, input_type: str, report_name: str) -> Optional[str]:
        """
        Generate a batch summary report for all scanned actions.
        
        Args:
            input_type: Type of input that was processed
            report_name: Name for the batch report
            
        Returns:
            Path to generated batch report or None if failed
        """
        if not self.generated_reports:
            return None
        
        try:
            # Prepare batch data
            actions_data = []
            for report_info in self.generated_reports:
                scan_data = self.report_generator._load_json_file(report_info['scan_result_path'])
                if scan_data:
                    actions_data.append({
                        'action_ref': report_info['action_ref'],
                        'scan_data': scan_data,
                        'version': report_info['version'],
                        'commit_sha': report_info['commit_sha']
                    })
            
            # Generate batch report
            batch_report_path = self.report_generator.generate_batch_report(actions_data, report_name)
            return batch_report_path
            
        except Exception as e:
            logger.error(f"❌ Failed to generate batch summary report: {e}")
            return None
