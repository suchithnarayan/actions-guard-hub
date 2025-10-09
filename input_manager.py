#!/usr/bin/env python3
"""
Input Manager for GitHub Actions Security Scanner

This module provides flexible input handling for different types of inputs:
- Single GitHub action or list from file
- GitHub repositories (single or multiple)
- GitHub organization (collects all repos and actions)
"""

import os
import json
import yaml
import tempfile
import shutil
import zipfile
import logging
from enum import Enum
from typing import List, Set, Optional, Dict, Any
from github_auth import GitHubAuthManager
import requests

logger = logging.getLogger(__name__)

class InputType(Enum):
    """Enumeration of supported input types."""
    ACTIONS = "actions"
    REPOSITORIES = "repositories" 
    ORGANIZATION = "organization"

class GitHubInputManager:
    """
    Manages different types of inputs for GitHub Actions scanning.
    
    Supports:
    - Single GitHub action or list of actions from file
    - GitHub repositories (single or comma-separated list)
    - GitHub organization (collects all repos and their actions)
    """
    
    def __init__(self, auth_manager: GitHubAuthManager):
        """
        Initialize the input manager.
        
        Args:
            auth_manager: GitHubAuthManager instance for API access
        """
        self.auth_manager = auth_manager
        self.github_api_base_url = "https://api.github.com"
        
    def get_actions_list(self, input_type: InputType, input_value: str, input_file: Optional[str] = None) -> List[str]:
        """
        Get list of GitHub actions based on input type.
        
        Args:
            input_type: Type of input (actions, repositories, organization)
            input_value: Input value (action, repo, or org name)
            input_file: Optional file path for actions list
            
        Returns:
            List of GitHub action references
        """
        logger.info(f"Processing input type: {input_type.value}")
        
        if input_type == InputType.ACTIONS:
            return self._get_actions_from_input(input_value, input_file)
        elif input_type == InputType.REPOSITORIES:
            return self._get_actions_from_repositories(input_value)
        elif input_type == InputType.ORGANIZATION:
            return self._get_actions_from_organization(input_value)
        else:
            raise ValueError(f"Unsupported input type: {input_type}")
    
    def _get_actions_from_input(self, input_value: str, input_file: Optional[str] = None) -> List[str]:
        """
        Get actions from direct input or file.
        
        Args:
            input_value: Single action reference or comma-separated list
            input_file: Optional file path containing actions list
            
        Returns:
            List of action references
        """
        actions = []
        
        # If input_file is provided, read from file
        if input_file and os.path.exists(input_file):
            logger.info(f"Reading actions from file: {input_file}")
            with open(input_file, "r", encoding="utf-8") as f:
                actions = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            logger.info(f"Loaded {len(actions)} actions from file")
        
        # If input_value is provided, parse it
        if input_value:
            if ',' in input_value:
                # Multiple actions separated by comma
                value_actions = [action.strip() for action in input_value.split(',') if action.strip()]
                actions.extend(value_actions)
                logger.info(f"Added {len(value_actions)} actions from input value")
            else:
                # Single action
                actions.append(input_value.strip())
                logger.info(f"Added single action from input value: {input_value}")
        
        # Remove duplicates while preserving order
        unique_actions = []
        seen = set()
        for action in actions:
            if action not in seen:
                unique_actions.append(action)
                seen.add(action)
        
        logger.info(f"Total unique actions: {len(unique_actions)}")
        return unique_actions
    
    def _get_actions_from_repositories(self, repositories: str) -> List[str]:
        """
        Get actions from GitHub repositories.
        
        Args:
            repositories: Single repository or comma-separated list (owner/repo format)
            
        Returns:
            List of unique action references found in repositories
        """
        repo_list = [repo.strip() for repo in repositories.split(',') if repo.strip()]
        logger.info(f"Processing {len(repo_list)} repositories")
        
        all_actions = set()
        
        for repo in repo_list:
            if '/' not in repo:
                logger.warning(f"Invalid repository format: {repo}. Expected format: owner/repo")
                continue
                
            logger.info(f"Collecting actions from repository: {repo}")
            try:
                repo_actions = self._collect_actions_from_repo(repo)
                all_actions.update(repo_actions)
                logger.info(f"Found {len(repo_actions)} actions in {repo}")
            except Exception as e:
                logger.error(f"Error collecting actions from {repo}: {e}")
                continue
        
        unique_actions = list(all_actions)
        logger.info(f"Total unique actions from repositories: {len(unique_actions)}")
        return unique_actions
    
    def _get_actions_from_organization(self, organization: str) -> List[str]:
        """
        Get actions from all repositories in a GitHub organization.
        
        Args:
            organization: GitHub organization name
            
        Returns:
            List of unique action references found in organization
        """
        logger.info(f"Processing organization: {organization}")
        
        # Get all repositories in the organization
        repositories = self._get_org_repositories(organization)
        logger.info(f"Found {len(repositories)} repositories in organization {organization}")
        
        all_actions = set()
        
        for repo in repositories:
            logger.info(f"Collecting actions from repository: {repo}")
            try:
                repo_actions = self._collect_actions_from_repo(repo)
                all_actions.update(repo_actions)
                logger.info(f"Found {len(repo_actions)} actions in {repo}")
            except Exception as e:
                logger.error(f"Error collecting actions from {repo}: {e}")
                continue
        
        unique_actions = list(all_actions)
        logger.info(f"Total unique actions from organization {organization}: {len(unique_actions)}")
        return unique_actions
    
    def _get_org_repositories(self, organization: str) -> List[str]:
        """
        Get all repositories for a GitHub organization.
        
        Args:
            organization: GitHub organization name
            
        Returns:
            List of repository names in owner/repo format
        """
        repositories = []
        page = 1
        
        while True:
            url = f"{self.github_api_base_url}/orgs/{organization}/repos"
            params = {"per_page": 100, "page": page, "type": "all"}
            
            try:
                response = requests.get(url, headers=self.auth_manager.get_headers(), params=params)
                response.raise_for_status()
                
                repos_data = response.json()
                if not repos_data:
                    break
                
                for repo in repos_data:
                    repositories.append(repo['full_name'])
                
                # Check if there are more pages
                if 'Link' not in response.headers or 'rel="next"' not in response.headers['Link']:
                    break
                    
                page += 1
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logger.error(f"Organization '{organization}' not found or not accessible")
                else:
                    logger.error(f"Error fetching repositories for organization {organization}: {e}")
                break
            except Exception as e:
                logger.error(f"Error fetching repositories for organization {organization}: {e}")
                break
        
        return repositories
    
    def _collect_actions_from_repo(self, repo_full_name: str) -> List[str]:
        """
        Collect GitHub Actions from a specific repository.
        
        Args:
            repo_full_name: Repository in owner/repo format
            
        Returns:
            List of action references found in the repository
        """
        actions = []
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Download repository as zip
            download_url = f"{self.github_api_base_url}/repos/{repo_full_name}/zipball"
            response = requests.get(download_url, headers=self.auth_manager.get_headers())
            response.raise_for_status()
            
            # Save and extract zip file
            zip_path = os.path.join(temp_dir, "repo.zip")
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find the extracted directory
            extracted_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
            if not extracted_dirs:
                logger.warning(f"No directories found in extracted zip for {repo_full_name}")
                return actions
            
            repo_dir = os.path.join(temp_dir, extracted_dirs[0])
            
            # Look for workflows directory
            workflows_dir = os.path.join(repo_dir, ".github", "workflows")
            if not os.path.exists(workflows_dir):
                logger.info(f"No workflows directory found in {repo_full_name}")
                return actions
            
            # Process workflow files
            for filename in os.listdir(workflows_dir):
                if filename.endswith(('.yml', '.yaml')):
                    workflow_path = os.path.join(workflows_dir, filename)
                    
                    try:
                        with open(workflow_path, 'r', encoding='utf-8') as f:
                            workflow = yaml.safe_load(f)
                        
                        if not workflow or 'jobs' not in workflow:
                            continue
                        
                        # Extract actions from workflow jobs
                        for job_id, job in workflow['jobs'].items():
                            if not job or 'steps' not in job:
                                continue
                            
                            for step in job['steps']:
                                if 'uses' in step:
                                    action = step['uses']
                                    
                                    # Skip internal actions and reusable workflows
                                    if action.startswith('./'):
                                        continue
                                    if '.yml@' in action or '.yaml@' in action:
                                        continue
                                    
                                    actions.append(action)
                    
                    except Exception as e:
                        logger.warning(f"Error processing workflow file {filename} in {repo_full_name}: {e}")
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Repository '{repo_full_name}' not found or not accessible")
            else:
                logger.error(f"Error downloading repository {repo_full_name}: {e}")
        except Exception as e:
            logger.error(f"Error processing repository {repo_full_name}: {e}")
        
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir, ignore_errors=True)
        
        return actions
    
    @staticmethod
    def validate_input(input_type: InputType, input_value: str, input_file: Optional[str] = None) -> bool:
        """
        Validate input parameters.
        
        Args:
            input_type: Type of input
            input_value: Input value
            input_file: Optional input file
            
        Returns:
            True if input is valid, False otherwise
        """
        if input_type == InputType.ACTIONS:
            if not input_value and not input_file:
                logger.error("For actions input type, either input_value or input_file must be provided")
                return False
            if input_file and not os.path.exists(input_file):
                logger.error(f"Actions file not found: {input_file}")
                return False
                
        elif input_type == InputType.REPOSITORIES:
            if not input_value:
                logger.error("For repositories input type, input_value must be provided")
                return False
            # Validate repository format
            repos = [repo.strip() for repo in input_value.split(',')]
            for repo in repos:
                if '/' not in repo or len(repo.split('/')) != 2:
                    logger.error(f"Invalid repository format: {repo}. Expected format: owner/repo")
                    return False
                    
        elif input_type == InputType.ORGANIZATION:
            if not input_value:
                logger.error("For organization input type, input_value must be provided")
                return False
            if '/' in input_value:
                logger.error(f"Invalid organization name: {input_value}. Should not contain '/'")
                return False
        
        return True
    
    def get_input_summary(self, input_type: InputType, input_value: str, input_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a summary of the input configuration.
        
        Args:
            input_type: Type of input
            input_value: Input value
            input_file: Optional input file
            
        Returns:
            Dictionary with input summary information
        """
        summary = {
            "input_type": input_type.value,
            "input_value": input_value,
            "input_file": input_file
        }
        
        if input_type == InputType.ACTIONS:
            if input_file:
                summary["description"] = f"Actions from file: {input_file}"
                if input_value:
                    summary["description"] += f" and direct input: {input_value}"
            else:
                summary["description"] = f"Actions from direct input: {input_value}"
                
        elif input_type == InputType.REPOSITORIES:
            repos = [repo.strip() for repo in input_value.split(',')]
            summary["repository_count"] = len(repos)
            summary["description"] = f"Actions from {len(repos)} repositories: {', '.join(repos)}"
            
        elif input_type == InputType.ORGANIZATION:
            summary["description"] = f"Actions from organization: {input_value}"
        
        return summary


def create_input_manager_from_args(args, auth_manager: GitHubAuthManager) -> GitHubInputManager:
    """
    Create GitHubInputManager from command line arguments.
    
    Args:
        args: Parsed command line arguments
        auth_manager: GitHubAuthManager instance
        
    Returns:
        GitHubInputManager instance
    """
    return GitHubInputManager(auth_manager)


def get_input_type_from_args(args) -> InputType:
    """
    Determine input type from command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        InputType enum value
    """
    input_type_str = getattr(args, 'input_type', 'actions')
    
    try:
        return InputType(input_type_str.lower())
    except ValueError:
        valid_types = [t.value for t in InputType]
        raise ValueError(f"Invalid input type '{input_type_str}'. Valid types: {valid_types}")


def get_actions_from_args(args, auth_manager: GitHubAuthManager) -> List[str]:
    """
    Get list of actions from command line arguments.
    
    Args:
        args: Parsed command line arguments
        auth_manager: GitHubAuthManager instance
        
    Returns:
        List of GitHub action references
    """
    input_manager = create_input_manager_from_args(args, auth_manager)
    input_type = get_input_type_from_args(args)
    
    # Get input values from args
    input_value = getattr(args, 'input_value', None) or ""
    input_file = getattr(args, 'input_file', None)
    
    # For backward compatibility with --actions flag
    if not input_value and not input_file and hasattr(args, 'actions'):
        input_file = args.actions
        input_type = InputType.ACTIONS
    
    # Validate input
    if not GitHubInputManager.validate_input(input_type, input_value, input_file):
        raise ValueError("Invalid input configuration")
    
    # Get input summary
    summary = input_manager.get_input_summary(input_type, input_value, input_file)
    logger.info(f"Input configuration: {summary['description']}")
    
    # Get actions list
    return input_manager.get_actions_list(input_type, input_value, input_file)
