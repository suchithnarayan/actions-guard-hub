#!/usr/bin/env python3
"""
GitHub Client Module

This module handles all GitHub API interactions including:
- Repository metadata collection
- Release and tag information
- Contributors counting
- Action downloading
- Rate limiting and error handling

Author: GitHub Actions Security Scanner Team
License: MIT
"""

import os
import time
import logging
import tempfile
import shutil
import zipfile
import requests
import backoff
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from github_auth import GitHubAuthManager, AuthType

logger = logging.getLogger(__name__)


class GitHubClient:
    """
    GitHub API client with comprehensive repository and action management capabilities.
    
    Handles:
    - Repository statistics and metadata
    - Release and tag information
    - Action downloading and extraction
    - Rate limiting and authentication
    """
    
    def __init__(self, auth_manager: GitHubAuthManager):
        """
        Initialize GitHub client with authentication manager.
        
        Args:
            auth_manager: Initialized GitHub authentication manager
        """
        self.auth_manager = auth_manager
        self.api_base = "https://api.github.com"
        
        logger.debug("🔧 GitHub client initialized")
    
    @backoff.on_exception(
        backoff.expo,
        (requests.exceptions.RequestException, requests.exceptions.HTTPError),
        max_tries=3,
        giveup=lambda e: '404' in str(e)
    )
    def make_request(self, url: str, params: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Make a GitHub API request with retry logic and rate limiting.
        
        Args:
            url: GitHub API URL to request
            params: Optional query parameters
            
        Returns:
            Response object or None if failed
        """
        try:
            response = requests.get(
                url, 
                headers=self.auth_manager.get_headers(),
                params=params,
                timeout=30
            )
            
            # Handle rate limiting
            if response.status_code == 403:
                remaining = response.headers.get('X-RateLimit-Remaining', '0')
                if int(remaining) == 0:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', time.time()))
                    sleep_time = max(reset_time - int(time.time()) + 1, 60)
                    logger.warning(f"⏱️  Rate limit exceeded. Waiting {sleep_time} seconds...")
                    time.sleep(sleep_time)
                    return self.make_request(url, params)
            
            # Handle authentication errors
            if response.status_code == 401:
                if self.auth_manager.auth_type == AuthType.GITHUB_APP:
                    logger.info("🔄 Refreshing GitHub App token...")
                    self.auth_manager.refresh_token()
                    return self.make_request(url, params)
                else:
                    logger.error("❌ Authentication failed")
                    response.raise_for_status()
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"⚠️  Resource not found: {url}")
            raise
        except Exception as e:
            logger.error(f"❌ GitHub API request failed: {e}")
            raise
    
    def get_repository_info(self, owner: str, repo: str) -> Optional[Dict]:
        """
        Get basic repository information.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository information dictionary or None if failed
        """
        try:
            url = f"{self.api_base}/repos/{owner}/{repo}"
            response = self.make_request(url)
            
            if response:
                return response.json()
            return None
            
        except Exception as e:
            logger.error(f"❌ Failed to get repository info for {owner}/{repo}: {e}")
            return None
    
    def get_repository_stats(self, owner: str, repo: str) -> Optional[Dict]:
        """
        Collect comprehensive repository statistics and metadata.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Dictionary with repository statistics or None if failed
        """
        try:
            # Get basic repository information
            repo_data = self.get_repository_info(owner, repo)
            if not repo_data:
                return None
            
            # Get contributors count
            logger.info(f"🔍 Collecting contributors count for {owner}/{repo}...")
            contributors_count = self.get_contributors_count(owner, repo)
            logger.info(f"👥 Found {contributors_count} contributors for {owner}/{repo}")
            
            # Collect additional statistics
            stats = {
                'repository': {
                    'owner': owner,
                    'name': repo,
                    'created_at': repo_data.get('created_at'),
                    'stars': repo_data.get('stargazers_count', 0),
                    'issues': repo_data.get('open_issues_count', 0),
                    'contributors': contributors_count
                },
                'releases': {},
                'last_updated': datetime.now().isoformat()
            }
            
            # Get releases/tags information
            releases_data = self.get_releases_info(owner, repo)
            if releases_data:
                stats['releases'] = releases_data
            
            return stats
            
        except Exception as e:
            logger.warning(f"⚠️  Failed to collect stats for {owner}/{repo}: {e}")
            return None
    
    def get_releases_info(self, owner: str, repo: str) -> Dict:
        """
        Collect information about repository releases and tags.
        This method fetches ALL available releases, not just recent ones.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Dictionary with release information
        """
        releases_info = {}
        
        try:
            # Get ALL tags with pagination
            page = 1
            while True:
                tags_url = f"{self.api_base}/repos/{owner}/{repo}/tags"
                params = {"per_page": 100, "page": page}
                
                response = self.make_request(tags_url, params)
                if not response:
                    break
                    
                tags = response.json()
                if not tags:
                    break
                
                for tag in tags:
                    tag_name = tag['name']
                    commit_sha = tag['commit']['sha']
                    
                    releases_info[tag_name] = {
                        'published_date': 'N/A',
                        'scanned': False,
                        'latest': commit_sha,
                        'sha': [commit_sha],
                        'safe': True,
                        'scan_report': None
                    }
                
                # Check if there are more pages
                if 'Link' not in response.headers or 'rel="next"' not in response.headers['Link']:
                    break
                page += 1
                
                # Safety limit to prevent infinite loops
                if page > 50:  # Max 5000 tags
                    logger.warning(f"⚠️  Reached maximum page limit for tags in {owner}/{repo}")
                    break
            
            # Get ALL releases with pagination for published dates
            page = 1
            while True:
                releases_url = f"{self.api_base}/repos/{owner}/{repo}/releases"
                params = {"per_page": 100, "page": page}
                
                response = self.make_request(releases_url, params)
                if not response:
                    break
                    
                releases = response.json()
                if not releases:
                    break
                
                for release in releases:
                    tag_name = release['tag_name']
                    if tag_name in releases_info:
                        releases_info[tag_name]['published_date'] = release.get('published_at', 'N/A')
                
                # Check if there are more pages
                if 'Link' not in response.headers or 'rel="next"' not in response.headers['Link']:
                    break
                page += 1
                
                # Safety limit
                if page > 20:  # Max 2000 releases
                    logger.warning(f"⚠️  Reached maximum page limit for releases in {owner}/{repo}")
                    break
            
            logger.info(f"📊 Collected {len(releases_info)} releases/tags for {owner}/{repo}")
            
        except Exception as e:
            logger.warning(f"⚠️  Could not collect releases info for {owner}/{repo}: {e}")
        
        return releases_info
    
    def get_contributors_count(self, owner: str, repo: str) -> int:
        """
        Get the number of contributors for a repository using GitHub API.
        
        Uses simple pagination approach: make API calls until we get an empty response,
        then count all contributors from all pages.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Number of contributors
        """
        try:
            contributors_url = f"{self.api_base}/repos/{owner}/{repo}/contributors"
            total_count = 0
            page = 1
            
            logger.debug(f"Starting pagination for {owner}/{repo} contributors...")
            
            while True:
                # Get contributors for current page
                params = {"per_page": 100, "page": page, "anon": "true"}
                
                try:
                    response = self.make_request(contributors_url, params)
                    if not response:
                        break
                    
                    contributors = response.json()
                    
                    # If empty response, we've reached the end
                    if not contributors:
                        logger.debug(f"Empty response on page {page}, stopping pagination")
                        break
                    
                    # Add contributors from this page to total count
                    page_count = len(contributors)
                    total_count += page_count
                    
                    logger.debug(f"Page {page}: {page_count} contributors (total so far: {total_count})")
                    
                    # If we got less than 100 contributors, this is the last page
                    if page_count < 100:
                        logger.debug(f"Last page reached (got {page_count} < 100 contributors)")
                        break
                    
                    # Move to next page
                    page += 1
                    
                    # Safety limit to prevent infinite loops
                    if page > 50:  # Max 5000 contributors (50 pages * 100)
                        logger.warning(f"Reached maximum page limit (50) for {owner}/{repo}")
                        break
                        
                except requests.exceptions.Timeout:
                    logger.warning(f"⚠️  Timeout getting contributors for {owner}/{repo} (page {page})")
                    break
                except requests.exceptions.RequestException as e:
                    logger.warning(f"⚠️  Request error getting contributors for {owner}/{repo} (page {page}): {e}")
                    break
            
            logger.info(f"📊 Contributors count for {owner}/{repo}: {total_count} (from {page-1} pages)")
            return total_count
            
        except Exception as e:
            logger.error(f"❌ Exception getting contributors count for {owner}/{repo}: {e}")
            return 0
    
    def get_latest_release(self, owner: str, repo: str) -> Optional[Dict]:
        """
        Get the latest release for a repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Latest release information or None if not found
        """
        try:
            url = f"{self.api_base}/repos/{owner}/{repo}/releases/latest"
            response = self.make_request(url)
            
            if response and response.status_code == 200:
                return response.json()
            return None
            
        except Exception as e:
            logger.debug(f"No latest release found for {owner}/{repo}: {e}")
            return None
    
    def resolve_version_and_sha(self, owner: str, repo: str, version: str, 
                               existing_metadata: Optional[Dict] = None) -> Tuple[str, Optional[str]]:
        """
        Resolve version to actual release/tag and get commit SHA.
        
        Args:
            owner: Repository owner
            repo: Repository name
            version: Version to resolve (could be "latest", tag, or commit SHA)
            existing_metadata: Optional existing metadata to check first
            
        Returns:
            Tuple of (resolved_version, commit_sha)
        """
        try:
            owner_repo = f"{owner}/{repo}"
            
            # If version is already specific (not "latest"), return as-is
            if version not in ["latest", "main", "master", "prod", "production"]:
                # Check if it's already in our metadata
                if existing_metadata and owner_repo in existing_metadata:
                    releases = existing_metadata[owner_repo].get("releases", {})
                    if version in releases:
                        commit_sha = releases[version].get("latest")
                        return version, commit_sha
                    
                    # Check if it's a commit SHA
                    for release_name, release_info in releases.items():
                        for sha in release_info.get("sha", []):
                            if version == sha or sha.startswith(version):
                                return release_name, sha
                
                # Return as-is if not found in metadata
                return version, None
            
            logger.info(f"🔍 Resolving '{version}' to actual release for {owner_repo}...")
            
            # Check if we have releases in metadata
            if existing_metadata and owner_repo in existing_metadata:
                releases = existing_metadata[owner_repo].get("releases", {})
                
                if releases:
                    # Find the latest release by published date
                    latest_release = None
                    latest_date = None
                    
                    for release_name, release_info in releases.items():
                        published_date = release_info.get("published_date", "N/A")
                        if published_date != "N/A":
                            try:
                                date_obj = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                                if latest_date is None or date_obj > latest_date:
                                    latest_date = date_obj
                                    latest_release = release_name
                            except Exception:
                                continue
                    
                    if latest_release:
                        commit_sha = releases[latest_release].get("latest")
                        logger.info(f"✅ Resolved '{version}' to latest release: {latest_release}")
                        return latest_release, commit_sha
            
            # Try to get latest release from API
            logger.info(f"📡 Fetching latest release from GitHub API for {owner_repo}...")
            latest_release = self.get_latest_release(owner, repo)
            
            if latest_release:
                latest_version = latest_release.get("tag_name")
                commit_sha = latest_release.get("target_commitish")
                logger.info(f"✅ Resolved '{version}' to latest release from API: {latest_version}")
                return latest_version, commit_sha
            
            # Fallback to default branch
            logger.info(f"🌿 Falling back to default branch for {owner_repo}...")
            repo_info = self.get_repository_info(owner, repo)
            
            if repo_info:
                default_branch = repo_info.get("default_branch", "main")
                logger.info(f"✅ Resolved '{version}' to default branch: {default_branch}")
                return default_branch, None
            
            # Final fallback
            logger.warning(f"⚠️  Could not resolve '{version}' for {owner_repo}, using 'main' as fallback")
            return "main", None
            
        except Exception as e:
            logger.error(f"❌ Error resolving version for {owner}/{repo}@{version}: {e}")
            return version, None
    
    def download_action(self, owner: str, repo: str, version: str) -> Optional[str]:
        """
        Download GitHub action source code.
        
        Args:
            owner: Repository owner
            repo: Repository name
            version: Version/tag/branch to download
            
        Returns:
            Path to extracted action directory or None if failed
        """
        temp_dir = tempfile.mkdtemp(prefix="gha_scan_")
        
        try:
            logger.info(f"📥 Downloading {owner}/{repo}@{version}...")
            
            # Determine download URL based on version type
            download_url = None
            
            # Check if version looks like a release tag (v1.0.0, v1, etc.)
            if re.match(r'^v?\d+(\.\d+)*(-\w+)*$', version):
                # Try as release tag first
                download_url = f"https://github.com/{owner}/{repo}/archive/refs/tags/{version}.zip"
                logger.debug(f"🏷️ Trying as release tag: {download_url}")
            
            # Check if version looks like a commit SHA
            elif re.match(r'^[0-9a-fA-F]{7,40}$', version):
                # Try as commit SHA
                download_url = f"https://github.com/{owner}/{repo}/archive/{version}.zip"
                logger.debug(f"🔗 Trying as commit SHA: {download_url}")
            
            # Check if version is a branch name (main, master, dev, etc.)
            elif version in ["main", "master", "dev", "development", "prod", "production"] or not re.match(r'^v?\d', version):
                # Try as branch
                download_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{version}.zip"
                logger.debug(f"🌿 Trying as branch: {download_url}")
            
            else:
                # Default: try as tag first, then as branch
                download_url = f"https://github.com/{owner}/{repo}/archive/refs/tags/{version}.zip"
                logger.debug(f"🤷 Trying as tag (default): {download_url}")
            
            # Download the zip file
            zip_response = requests.get(download_url, stream=True, timeout=60)
            
            # If tag download fails and it's not obviously a SHA, try as branch
            if zip_response.status_code == 404 and not re.match(r'^[0-9a-fA-F]{7,40}$', version):
                logger.debug(f"🔄 Tag download failed, trying as branch...")
                download_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{version}.zip"
                zip_response = requests.get(download_url, stream=True, timeout=60)
            
            # If still failing and version looks like it could be a commit, try that
            if zip_response.status_code == 404 and len(version) >= 7:
                logger.debug(f"🔄 Branch download failed, trying as commit...")
                download_url = f"https://github.com/{owner}/{repo}/archive/{version}.zip"
                zip_response = requests.get(download_url, stream=True, timeout=60)
            
            zip_response.raise_for_status()
            logger.info(f"✅ Successfully downloaded from: {download_url}")
            
            # Extract the zip file
            zip_path = Path(temp_dir) / "action.zip"
            with open(zip_path, 'wb') as f:
                for chunk in zip_response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find the extracted directory
            extracted_dirs = [d for d in Path(temp_dir).iterdir() if d.is_dir()]
            if extracted_dirs:
                logger.debug(f"📁 Extracted to: {extracted_dirs[0]}")
                return str(extracted_dirs[0])
            
            logger.error(f"❌ No directories found in extracted zip for {owner}/{repo}@{version}")
            return None
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.error(f"❌ Action not found: {owner}/{repo}@{version} (tried: {download_url})")
            else:
                logger.error(f"❌ HTTP error downloading {owner}/{repo}@{version}: {e}")
            if Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            return None
        except Exception as e:
            logger.error(f"❌ Failed to download action {owner}/{repo}@{version}: {e}")
            if Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            return None
    
    def parse_action_reference(self, action_ref: str) -> Tuple[Optional[str], Optional[str], str]:
        """
        Parse action reference into owner, repo, and version components.
        
        Args:
            action_ref: Action reference string
            
        Returns:
            Tuple of (owner, repo, version) or (None, None, version) if invalid
        """
        try:
            if action_ref.startswith("http"):
                # URL format: https://github.com/owner/repo
                owner_repo = action_ref.split("github.com/")[1].rstrip("/")
                version = "latest"
            else:
                # Reference format: owner/repo@version
                if '@' in action_ref:
                    owner_repo, version = action_ref.split('@', 1)
                else:
                    owner_repo = action_ref
                    version = "latest"
            
            # Validate format
            if '/' not in owner_repo or len(owner_repo.split('/')) != 2:
                logger.error(f"❌ Invalid repository format: {owner_repo}")
                return None, None, version
            
            owner, repo = owner_repo.split('/', 1)
            return owner, repo, version
            
        except Exception as e:
            logger.error(f"❌ Error parsing action reference {action_ref}: {e}")
            return None, None, "latest"
