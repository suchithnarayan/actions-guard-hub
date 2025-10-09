#!/usr/bin/env python3
"""
Actions Guard Hub

A comprehensive security analysis tool for GitHub Actions that provides:
- Multi-input support (actions, repositories, organizations)
- Flexible authentication (GitHub App, PAT, no-auth)
- AI-powered security analysis using Google Gemini
- Human-readable reports and batch summaries
- Web-based dashboard for results visualization

Author: GitHub Actions Security Scanner Team
License: MIT
Version: 2.0.0
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Core modules
from github_auth import GitHubAuthManager, create_auth_manager_from_args
from input_manager import get_actions_from_args, get_input_type_from_args
from report_generator import ScanReportGenerator
from scanner_core import GitHubActionsScanner
from utils.overview_generator import generate_security_overview

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('gha_scanner.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception as e:
    logger.warning(f"❌ Failed to load environment variables from .env file: {e}")
    logger.warning("Make sure you have a .env file in the root of the project")

# Application constants
APP_NAME = "GitHub Actions Security Scanner"
APP_VERSION = "2.0.0"
DEFAULT_OUTPUT_DIR = "frontend/output"
DEFAULT_REPORTS_DIR = "scan-reports"
DEFAULT_METADATA_DIR = "frontend/output-metadata"
DEFAULT_STATS_FILE = "frontend/action-stats.json"


class GHASecurityScanner:
    """
    Main application class for the GitHub Actions Security Scanner.
    
    This class orchestrates the entire scanning process, from input validation
    to report generation, providing a clean interface for security analysis
    of GitHub Actions.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: Dictionary containing scanner configuration
        """
        self.config = config
        self.auth_manager = None
        self.scanner = None
        self.reports_generated = []
        
        # Setup directories
        self._setup_directories()
        
        logger.info(f"🚀 Initializing {APP_NAME} v{APP_VERSION}")
    
    def validate_ai_model_setup(self) -> bool:
        """
        Validate AI model setup and configuration.
        
        Returns:
            True if AI model setup is valid, False otherwise
        """
        try:
            from ai_core import validate_model_setup, AICore
            
            ai_model = self.config.get('ai_model', 'gemini')
            model_name = self.config.get('model_name')
            
            logger.info(f"🤖 Validating AI model setup: {ai_model}")
            
            # Validate model setup
            is_valid, error_message = validate_model_setup(ai_model)
            
            if not is_valid:
                logger.error(f"❌ AI model validation failed: {error_message}")
                
                # Show helpful setup information
                env_vars = AICore.get_required_env_vars()
                if ai_model in env_vars:
                    env_var = env_vars[ai_model]
                    logger.info(f"💡 Required environment variable: {env_var}")
                    logger.info(f"💡 Set it with: export {env_var}=your_api_key_here")
                
                available_models = AICore.get_available_models()
                if available_models:
                    logger.info("💡 Available models:")
                    for provider, models in available_models.items():
                        logger.info(f"   {provider}: {', '.join(models)}")
                else:
                    logger.info("💡 Install LangChain packages:")
                    logger.info("   pip install langchain-google-genai  # for Gemini")
                    logger.info("   pip install langchain-openai        # for OpenAI")
                
                return False
            
            # Test model initialization
            try:
                from ai_core import create_ai_core
                test_ai = create_ai_core(ai_model, model_name)
                model_info = test_ai.get_model_info()
                logger.info(f"✅ AI model validated: {model_info['provider']}/{model_info['model']}")
                return True
                
            except Exception as e:
                logger.error(f"❌ Failed to initialize AI model: {e}")
                return False
            
        except Exception as e:
            logger.error(f"❌ AI model validation error: {e}")
            return False
    
    def _setup_directories(self):
        """Create necessary directories for output and reports."""
        directories = [
            self.config['output_dir'],
            self.config['metadata_dir'],
            self.config['reports_dir']
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            logger.debug(f"📁 Ensured directory exists: {directory}")
    
    def initialize_authentication(self, args) -> bool:
        """
        Initialize and validate authentication.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            logger.info("🔐 Initializing authentication...")
            self.auth_manager = create_auth_manager_from_args(args)
            
            # Validate authentication
            if not self.auth_manager.validate_token():
                logger.error("❌ Authentication validation failed")
                return False
            
            # Display rate limit information
            rate_info = self.auth_manager.get_rate_limit_info()
            logger.info(
                f"✅ Authentication successful: {self.auth_manager.auth_type.value} "
                f"({rate_info['requests_per_hour']} requests/hour)"
            )
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Authentication initialization failed: {e}")
            return False
    
    def initialize_scanner(self) -> bool:
        """
        Initialize the core scanner component.
        
        Returns:
            True if scanner initialized successfully, False otherwise
        """
        try:
            logger.info("🔧 Initializing scanner core...")
            
            self.scanner = GitHubActionsScanner(
                config=self.config,
                auth_manager=self.auth_manager
            )
            
            # Load existing metadata if available
            if Path(self.config['stats_file']).exists():
                self.scanner.load_existing_metadata(self.config['stats_file'])
                logger.info(f"📊 Loaded existing metadata from {self.config['stats_file']}")
            
            # Load security analysis prompt
            if not self.scanner.load_prompt(self.config['prompt_file']):
                logger.error(f"❌ Failed to load prompt from {self.config['prompt_file']}")
                return False
            
            logger.info("✅ Scanner core initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Scanner initialization failed: {e}")
            return False
    
    def process_actions(self, args) -> List[str]:
        """
        Process input arguments to get list of actions to scan.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            List of GitHub action references to scan
        """
        try:
            logger.info("📋 Processing input arguments...")
            
            actions_list = get_actions_from_args(args, self.auth_manager)
            
            if not actions_list:
                logger.error("❌ No actions found to process")
                return []
            
            input_type = get_input_type_from_args(args)
            logger.info(
                f"✅ Found {len(actions_list)} actions to scan "
                f"(input type: {input_type.value})"
            )
            
            # Log sample of actions for verification
            if len(actions_list) <= 5:
                logger.info(f"📝 Actions to scan: {', '.join(actions_list)}")
            else:
                logger.info(
                    f"📝 First 5 actions: {', '.join(actions_list[:5])}... "
                    f"(+{len(actions_list) - 5} more)"
                )
            
            return actions_list
            
        except Exception as e:
            logger.error(f"❌ Error processing input: {e}")
            return []
    
    def scan_actions(self, actions_list: List[str], skip_ai_scan: bool = False) -> bool:
        """
        Perform security scanning on the list of actions.
        
        Args:
            actions_list: List of GitHub action references to scan
            skip_ai_scan: Whether to skip AI analysis (metadata only)
            
        Returns:
            True if scanning completed successfully, False otherwise
        """
        try:
            logger.info(f"🔍 Starting security scan of {len(actions_list)} actions...")
            
            if skip_ai_scan:
                logger.info("⏭️  AI analysis disabled - collecting metadata only")
            
            success_count = 0
            error_count = 0
            
            for i, action_ref in enumerate(actions_list, 1):
                logger.info(f"\n{'='*60}")
                logger.info(f"🎯 Scanning action {i}/{len(actions_list)}: {action_ref}")
                logger.info(f"{'='*60}")
                
                try:
                    result = self.scanner.scan_action(action_ref, skip_ai_scan)
                    
                    if result['success']:
                        success_count += 1
                        
                        if result.get('report_path'):
                            self.reports_generated.append({
                                'action_ref': action_ref,
                                'report_path': result['report_path'],
                                'scan_type': result.get('scan_type', 'new')
                            })
                            logger.info(f"📄 Report: {result['report_path']}")
                    else:
                        error_count += 1
                        logger.warning(f"⚠️  Scan failed for {action_ref}: {result.get('error', 'Unknown error')}")
                
                except Exception as e:
                    error_count += 1
                    logger.error(f"❌ Error scanning {action_ref}: {e}")
                
                # Rate limiting pause between scans
                if i < len(actions_list):
                    logger.info("⏱️  Pausing between scans to respect rate limits...")
                    # Update security overview after each scan
                self._update_security_overview()
            
            logger.info(f"\n🏁 Scanning completed: {success_count} successful, {error_count} errors")
            return error_count == 0
            
        except Exception as e:
            logger.error(f"❌ Scanning process failed: {e}")
            return False
    
    def generate_batch_report(self, input_type: str) -> Optional[str]:
        """
        Generate a batch summary report for all scanned actions.
        
        Args:
            input_type: Type of input that was processed
            
        Returns:
            Path to generated batch report, or None if failed
        """
        if not self.reports_generated:
            logger.info("ℹ️  No reports to summarize")
            return None
        
        try:
            logger.info(f"📊 Generating batch summary report...")
            
            batch_report_path = self.scanner.generate_batch_summary_report(
                input_type, 
                f"{input_type}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            
            if batch_report_path:
                logger.info(f"✅ Batch report generated: {batch_report_path}")
            
            return batch_report_path
            
        except Exception as e:
            logger.error(f"❌ Batch report generation failed: {e}")
            return None
    
    def _update_security_overview(self):
        """Update the security overview for the web dashboard."""
        try:
            generate_security_overview(
                self.config['output_dir'],
                "security-overview.json",
                Path(self.config['output_dir']).name
            )
        except Exception as e:
            logger.debug(f"Failed to update security overview: {e}")
    
    def display_results_summary(self, batch_report_path: Optional[str] = None):
        """
        Display a summary of all generated reports.
        
        Args:
            batch_report_path: Path to batch report if generated
        """
        if not self.reports_generated and not batch_report_path:
            logger.info("ℹ️  No reports were generated")
            return
        
        logger.info(f"\n{'='*80}")
        logger.info("📋 SCAN RESULTS SUMMARY")
        logger.info(f"{'='*80}")
        
        if self.reports_generated:
            logger.info(f"📄 Individual Reports Generated: {len(self.reports_generated)}")
            
            for i, report_info in enumerate(self.reports_generated, 1):
                scan_type_emoji = "🔄" if report_info['scan_type'] == 'existing' else "🆕"
                logger.info(f"  {i}. {scan_type_emoji} {report_info['action_ref']}")
                logger.info(f"     📁 {report_info['report_path']}")
        
        if batch_report_path:
            logger.info(f"\n📊 Batch Summary Report:")
            logger.info(f"     📁 {batch_report_path}")
        
        logger.info(f"\n📂 All reports saved in: {Path(self.config['reports_dir']).absolute()}")
        logger.info(f"🌐 Web dashboard: Open frontend/index.html in your browser")
        logger.info(f"{'='*80}")


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the command line argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='gha-security-scanner',
        description=f"{APP_NAME} v{APP_VERSION} - Comprehensive security analysis for GitHub Actions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single action
  python actionsguardhub.py --input-type actions --input-value "actions/checkout@v4"
  
  # Scan multiple actions
  python actionsguardhub.py --input-type actions --input-value "actions/checkout@v4,actions/setup-node@v3"
  
  # Scan all actions in a repository
  python actionsguardhub.py --input-type repositories --input-value "microsoft/vscode"
  
  # Scan all actions in an organization
  python actionsguardhub.py --input-type organization --input-value "microsoft"
  
  # Use Personal Access Token
  python actionsguardhub.py --auth-type pat_token --github-pat-token YOUR_TOKEN
  
  # Metadata collection only (no AI analysis)
  python actionsguardhub.py --skip-ai-scan --input-type repositories --input-value "actions/checkout"

Authentication:
  Set environment variables or use command line arguments:
  - GitHub App: GITHUB_APP_CLIENT_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_APP_INSTALLATION_ID
  - PAT Token: GITHUB_PAT_TOKEN or GITHUB_TOKEN

AI Models:
  Set API keys for your chosen AI provider:
  - Google Gemini: GOOGLE_API_KEY (default provider)
  - OpenAI: OPENAI_API_KEY (optional)
  - Legacy Gemini: GEMINI_API_KEY (still supported)

IMPORTANT DISCLAIMER:
  This tool uses AI models for security analysis. AI may produce false positives
  (flagging safe code as risky) or false negatives (missing actual vulnerabilities).
  Always have security experts review AI-generated findings before making critical
  security decisions. See documentation for detailed limitations and best practices.

For more information, visit: https://github.com/your-org/gha-security-scanner
        """
    )
    
    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        '--input-type',
        choices=['actions', 'repositories', 'organization'],
        default='actions',
        help='Type of input to process (default: actions)'
    )
    input_group.add_argument(
        '--input-value',
        help='Input value: action reference, repository (owner/repo), or organization name'
    )
    input_group.add_argument(
        '--input-file',
        help='File containing list of actions (for actions input type)'
    )
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument(
        '--auth-type',
        choices=['github_app', 'pat_token', 'no_auth'],
        default='pat_token',
        help='Authentication method (default: pat_token)'
    )
    auth_group.add_argument(
        '--github-app-client-id',
        help='GitHub App Client ID (or set GITHUB_APP_CLIENT_ID env var)'
    )
    auth_group.add_argument(
        '--github-app-private-key',
        help='GitHub App Private Key (or set GITHUB_APP_PRIVATE_KEY env var)'
    )
    auth_group.add_argument(
        '--github-app-installation-id',
        help='GitHub App Installation ID (or set GITHUB_APP_INSTALLATION_ID env var)'
    )
    auth_group.add_argument(
        '--github-pat-token',
        help='GitHub Personal Access Token (or set GITHUB_PAT_TOKEN env var)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output-dir',
        default=DEFAULT_OUTPUT_DIR,
        help=f'Output directory for scan results (default: {DEFAULT_OUTPUT_DIR})'
    )
    output_group.add_argument(
        '--reports-dir',
        default=DEFAULT_REPORTS_DIR,
        help=f'Directory for human-readable reports (default: {DEFAULT_REPORTS_DIR})'
    )
    output_group.add_argument(
        '--metadata-dir',
        default=DEFAULT_METADATA_DIR,
        help=f'Directory for scan metadata (default: {DEFAULT_METADATA_DIR})'
    )
    output_group.add_argument(
        '--stats-file',
        default=DEFAULT_STATS_FILE,
        help=f'File for action statistics (default: {DEFAULT_STATS_FILE})'
    )
    
    # Scanning options
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument(
        '--prompt-file',
        default='prompt.txt',
        help='File containing the security analysis prompt (default: prompt.txt)'
    )
    scan_group.add_argument(
        '--skip-ai-scan',
        action='store_true',
        help='Skip AI analysis and collect metadata only'
    )
    
    # AI Model options
    ai_group = parser.add_argument_group('AI Model Options')
    ai_group.add_argument(
        '--ai-model',
        choices=['gemini', 'openai'],
        default='gemini',
        help='AI model provider to use (default: gemini)'
    )
    ai_group.add_argument(
        '--model-name',
        help='Specific model name (e.g., gemini-2.5-flash, gpt-4o-mini, o1-mini)'
    )
    
    # Legacy compatibility
    legacy_group = parser.add_argument_group('Legacy Compatibility')
    legacy_group.add_argument(
        '--actions',
        help='[DEPRECATED] Use --input-type actions --input-file instead'
    )
    
    # General options
    parser.add_argument(
        '--version',
        action='version',
        version=f'{APP_NAME} v{APP_VERSION}'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    return parser


def main():
    """Main entry point for the GitHub Actions Security Scanner."""
    
    # Parse command line arguments
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("🐛 Verbose logging enabled")
    
    # Create configuration
    config = {
        'output_dir': args.output_dir,
        'metadata_dir': args.metadata_dir,
        'reports_dir': args.reports_dir,
        'stats_file': args.stats_file,
        'prompt_file': args.prompt_file,
        'ai_model': args.ai_model,
        'model_name': args.model_name,
    }
    
    # Initialize scanner
    scanner_app = GHASecurityScanner(config)
    
    try:
        # Validate AI model setup
        if not args.skip_ai_scan:
            if not scanner_app.validate_ai_model_setup():
                logger.error("❌ AI model setup validation failed")
                sys.exit(1)
        
        # Initialize authentication
        if not scanner_app.initialize_authentication(args):
            logger.error("❌ Failed to initialize authentication")
            sys.exit(1)
        
        # Initialize scanner core
        if not scanner_app.initialize_scanner():
            logger.error("❌ Failed to initialize scanner")
            sys.exit(1)
        
        # Process input to get actions list
        actions_list = scanner_app.process_actions(args)
        if not actions_list:
            logger.error("❌ No actions to scan")
            sys.exit(1)
        
        # Perform scanning
        if not scanner_app.scan_actions(actions_list, args.skip_ai_scan):
            logger.warning("⚠️  Some scans failed, but continuing...")
        
        # Generate batch report
        input_type = get_input_type_from_args(args)
        batch_report_path = scanner_app.generate_batch_report(input_type.value)
        
        # Display results summary
        scanner_app.display_results_summary(batch_report_path)
        
        logger.info("🎉 Scanning completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("\n⏹️  Scanning interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        if args.verbose:
            logger.exception("Full traceback:")
        sys.exit(1)


if __name__ == "__main__":
    main()
