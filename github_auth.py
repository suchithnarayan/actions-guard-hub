#!/usr/bin/env python3
"""
GitHub Authentication Manager

This module provides a flexible authentication system for GitHub API access
supporting multiple authentication methods: GitHub App, Personal Access Token (PAT),
and no authentication (with rate limiting warnings).
"""

import os
import time
import logging
import requests
import jwt
from enum import Enum
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AuthType(Enum):
    """Enumeration of supported authentication types."""
    GITHUB_APP = "github_app"
    PAT_TOKEN = "pat_token"
    NO_AUTH = "no_auth"

class GitHubAuthManager:
    """
    Manages GitHub API authentication with support for multiple authentication methods.
    
    Supports:
    - GitHub App authentication (highest rate limits)
    - Personal Access Token (PAT) authentication (good rate limits)
    - No authentication (lowest rate limits with warnings)
    """
    
    def __init__(self, auth_type: AuthType, **auth_config):
        """
        Initialize the GitHub authentication manager.
        
        Args:
            auth_type (AuthType): The type of authentication to use
            **auth_config: Authentication configuration parameters
                For GITHUB_APP: client_id, private_key, installation_id
                For PAT_TOKEN: token
                For NO_AUTH: no additional parameters needed
        """
        self.auth_type = auth_type
        self.auth_config = auth_config
        self.github_token = None
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        # Rate limit information for different auth types
        self.rate_limits = {
            AuthType.GITHUB_APP: {"requests_per_hour": 15000, "description": "GitHub App"},
            AuthType.PAT_TOKEN: {"requests_per_hour": 5000, "description": "Personal Access Token"},
            AuthType.NO_AUTH: {"requests_per_hour": 60, "description": "No Authentication"}
        }
        
        self._initialize_authentication()
    
    def _initialize_authentication(self):
        """Initialize authentication based on the selected auth type."""
        if self.auth_type == AuthType.GITHUB_APP:
            self._initialize_github_app_auth()
        elif self.auth_type == AuthType.PAT_TOKEN:
            self._initialize_pat_auth()
        elif self.auth_type == AuthType.NO_AUTH:
            self._initialize_no_auth()
        else:
            raise ValueError(f"Unsupported authentication type: {self.auth_type}")
    
    def _initialize_github_app_auth(self):
        """Initialize GitHub App authentication."""
        required_fields = ['client_id', 'private_key', 'installation_id']
        missing_fields = [field for field in required_fields if field not in self.auth_config]
        
        if missing_fields:
            raise ValueError(f"Missing required GitHub App configuration: {missing_fields}")
        
        logger.info("Initializing GitHub App authentication...")
        try:
            self.github_token = self._get_github_app_token(
                self.auth_config['client_id'],
                self.auth_config['private_key'],
                self.auth_config['installation_id']
            )
            self.headers['Authorization'] = f'token {self.github_token}'
            logger.info("GitHub App authentication initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize GitHub App authentication: {e}")
            raise
    
    def _initialize_pat_auth(self):
        """Initialize Personal Access Token authentication."""
        if 'token' not in self.auth_config:
            raise ValueError("Missing required PAT token configuration")
        
        logger.info("Initializing Personal Access Token authentication...")
        self.github_token = self.auth_config['token']
        self.headers['Authorization'] = f'token {self.github_token}'
        logger.info("Personal Access Token authentication initialized successfully")
    
    def _initialize_no_auth(self):
        """Initialize no authentication mode with warnings."""
        logger.warning("=" * 60)
        logger.warning("WARNING: Running without authentication!")
        logger.warning("Rate limits are severely restricted:")
        logger.warning(f"- Only {self.rate_limits[AuthType.NO_AUTH]['requests_per_hour']} requests per hour")
        logger.warning("- You may hit rate limits quickly when collecting metadata")
        logger.warning("- Consider using PAT token or GitHub App for better performance")
        logger.warning("=" * 60)
        
        # No authorization header for no auth
        self.github_token = None
    
    def _get_github_app_token(self, client_id: str, private_key: str, installation_id: str) -> str:
        """
        Generate a GitHub App installation access token.
        
        Args:
            client_id: GitHub App client ID
            private_key: GitHub App private key (PEM format)
            installation_id: GitHub App installation ID
            
        Returns:
            Installation access token
        """
        logger.info("Generating GitHub App token...")
        
        # Ensure private key is properly formatted
        if not private_key.startswith('-----BEGIN'):
            private_key = f"-----BEGIN RSA PRIVATE KEY-----\n{private_key}\n-----END RSA PRIVATE KEY-----"
        
        signing_key = private_key.encode('utf-8')
        
        # Create JWT payload
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 120,  # 2 minutes maximum
            'iss': client_id
        }
        
        # Create JWT
        encoded_jwt = jwt.encode(payload, signing_key, algorithm='RS256')
        
        # Request installation access token
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {encoded_jwt}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        response = requests.post(url, headers=headers)
        
        if response.status_code == 201:
            logger.info("Successfully generated GitHub App token")
            return response.json()['token']
        else:
            error_msg = f"Failed to obtain installation access token. Status: {response.status_code}"
            if response.content:
                try:
                    error_details = response.json()
                    error_msg += f", Details: {error_details}"
                except:
                    error_msg += f", Response: {response.text}"
            logger.error(error_msg)
            raise Exception(error_msg)
    
    def refresh_token(self):
        """Refresh the authentication token if applicable."""
        if self.auth_type == AuthType.GITHUB_APP:
            logger.info("Refreshing GitHub App token...")
            try:
                # Revoke current token if it exists
                if self.github_token:
                    self._revoke_github_app_token(self.github_token)
                
                # Generate new token
                self.github_token = self._get_github_app_token(
                    self.auth_config['client_id'],
                    self.auth_config['private_key'],
                    self.auth_config['installation_id']
                )
                self.headers['Authorization'] = f'token {self.github_token}'
                logger.info("GitHub App token refreshed successfully")
            except Exception as e:
                logger.error(f"Failed to refresh GitHub App token: {e}")
                raise
        elif self.auth_type == AuthType.PAT_TOKEN:
            logger.warning("PAT tokens cannot be refreshed automatically. Please update your token if needed.")
        elif self.auth_type == AuthType.NO_AUTH:
            logger.info("No token to refresh for no-auth mode")
    
    def _revoke_github_app_token(self, token: str):
        """Revoke a GitHub App installation access token."""
        url = "https://api.github.com/installation/token"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
        response = requests.delete(url, headers=headers)
        
        if response.status_code == 204:
            logger.info("GitHub App token revoked successfully")
        else:
            logger.warning(f"Failed to revoke token. Status: {response.status_code}")
    
    def get_headers(self) -> Dict[str, str]:
        """Get the headers for GitHub API requests."""
        return self.headers.copy()
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get rate limit information for the current auth type."""
        return self.rate_limits[self.auth_type].copy()
    
    def validate_token(self) -> bool:
        """
        Validate the current authentication by making a test API call.
        
        Returns:
            True if authentication is valid, False otherwise
        """
        try:
            url = "https://api.github.com/rate_limit"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                rate_limit_data = response.json()
                remaining = rate_limit_data.get('rate', {}).get('remaining', 0)
                limit = rate_limit_data.get('rate', {}).get('limit', 0)
                
                logger.info(f"Authentication valid. Rate limit: {remaining}/{limit}")
                
                # Warn if rate limit is low
                if remaining < 100:
                    logger.warning(f"Low rate limit remaining: {remaining}/{limit}")
                
                return True
            else:
                logger.error(f"Authentication validation failed. Status: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error validating authentication: {e}")
            return False
    
    @classmethod
    def create_from_config(cls, auth_type_str: str, **kwargs):
        """
        Create GitHubAuthManager from string auth type and configuration.
        
        Args:
            auth_type_str: String representation of auth type
            **kwargs: Authentication configuration
            
        Returns:
            GitHubAuthManager instance
        """
        try:
            auth_type = AuthType(auth_type_str.lower())
        except ValueError:
            valid_types = [t.value for t in AuthType]
            raise ValueError(f"Invalid auth type '{auth_type_str}'. Valid types: {valid_types}")
        
        return cls(auth_type, **kwargs)
    
    @classmethod
    def create_from_env(cls, auth_type_str: str):
        """
        Create GitHubAuthManager from environment variables.
        
        Args:
            auth_type_str: String representation of auth type
            
        Returns:
            GitHubAuthManager instance
        """
        auth_type = AuthType(auth_type_str.lower())
        
        if auth_type == AuthType.GITHUB_APP:
            config = {
                'client_id': os.getenv('GITHUB_APP_CLIENT_ID'),
                'private_key': os.getenv('GITHUB_APP_PRIVATE_KEY'),
                'installation_id': os.getenv('GITHUB_APP_INSTALLATION_ID')
            }
            
            missing = [k for k, v in config.items() if not v]
            if missing:
                raise ValueError(f"Missing environment variables for GitHub App: {missing}")
                
        elif auth_type == AuthType.PAT_TOKEN:
            token = os.getenv('GITHUB_PAT_TOKEN') or os.getenv('GITHUB_TOKEN')
            if not token:
                raise ValueError("Missing environment variable: GITHUB_PAT_TOKEN or GITHUB_TOKEN")
            config = {'token': token}
            
        elif auth_type == AuthType.NO_AUTH:
            config = {}
        
        return cls(auth_type, **config)


def create_auth_manager_from_args(args) -> GitHubAuthManager:
    """
    Create GitHubAuthManager from command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        GitHubAuthManager instance
    """
    auth_type_str = getattr(args, 'auth_type', 'pat_token')
    
    try:
        auth_type = AuthType(auth_type_str.lower())
    except ValueError:
        valid_types = [t.value for t in AuthType]
        raise ValueError(f"Invalid auth type '{auth_type_str}'. Valid types: {valid_types}")
    
    if auth_type == AuthType.GITHUB_APP:
        config = {
            'client_id': getattr(args, 'github_app_client_id', None) or os.getenv('GITHUB_APP_CLIENT_ID'),
            'private_key': getattr(args, 'github_app_private_key', None) or os.getenv('GITHUB_APP_PRIVATE_KEY'),
            'installation_id': getattr(args, 'github_app_installation_id', None) or os.getenv('GITHUB_APP_INSTALLATION_ID')
        }
        
        missing = [k for k, v in config.items() if not v]
        if missing:
            raise ValueError(f"Missing GitHub App configuration: {missing}")
            
    elif auth_type == AuthType.PAT_TOKEN:
        token = getattr(args, 'github_pat_token', None) or os.getenv('GITHUB_PAT_TOKEN') or os.getenv('GITHUB_TOKEN')
        if not token:
            raise ValueError("Missing GitHub PAT token. Use --github-pat-token or set GITHUB_PAT_TOKEN/GITHUB_TOKEN environment variable")
        config = {'token': token}
        
    elif auth_type == AuthType.NO_AUTH:
        config = {}
    
    return GitHubAuthManager(auth_type, **config)
