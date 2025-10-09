#!/usr/bin/env python3
"""
File Processor Module

This module handles file extraction, processing, and content analysis for GitHub Actions.
It provides utilities for extracting relevant files from downloaded actions and preparing
them for security analysis.

Features:
- Action file extraction with intelligent filtering
- Content type detection
- File size and security filtering
- Metadata extraction

Author: GitHub Actions Security Scanner Team
License: MIT
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class FileProcessor:
    """
    Handles file extraction and processing for GitHub Actions analysis.
    
    This class provides utilities for:
    - Extracting relevant files from downloaded actions
    - Filtering out unnecessary files (binaries, dependencies, etc.)
    - Preparing file contents for AI analysis
    - Metadata extraction and validation
    """
    
    def __init__(self, max_file_size: int = 512 * 1024):  # 512KB default
        """
        Initialize file processor.
        
        Args:
            max_file_size: Maximum file size to process (in bytes)
        """
        self.max_file_size = max_file_size
        
        # Files and directories to exclude (blacklist)
        self.exclude_dirs = {
            "node_modules", "venv", ".git", "dist", "build", "test", ".github",
            "__pycache__", ".pytest_cache", "jest", "__tests__", "__test__",
            "tests", "docs", "__mocks__", "__snapshots__", "examples", ".cargo",
            "target", "coverage", ".nyc_output", "lib", "vendor", "bin"
        }
        
        self.exclude_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
            ".ttf", ".eot", ".min.js", ".min.css", ".lock", ".log", ".md5",
            ".mp4", ".mp3", ".mov", ".bin", ".exe", ".zip", ".map", ".toml", ".md",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".tar", ".gz"
        }
        
        self.exclude_files = {
            "README.md", "LICENSE", "CHANGELOG.md", "package-lock.json",
            ".gitignore", ".npmignore", ".eslintrc.json", "tsconfig.json", 
            ".dockerignore", ".gitattributes", ".ignore", ".pre-commit-config.yaml", 
            ".pre-commit-hooks.yaml", "LICENSE-APACHE", "LICENSE-MIT", "yarn.lock",
            "Cargo.lock", "composer.lock", "Pipfile.lock", "poetry.lock"
        }
        
        # Priority files (always include if found)
        self.priority_files = {
            "action.yml", "action.yaml", "Dockerfile", "entrypoint.sh", 
            "main.py", "index.js", "main.js", "run.py", "execute.py"
        }
        
        logger.debug("📁 File processor initialized")
    
    def extract_action_files(self, action_dir: str) -> Dict[str, str]:
        """
        Extract relevant files from downloaded action for analysis.
        
        Args:
            action_dir: Path to extracted action directory
            
        Returns:
            Dictionary mapping file paths to their contents
        """
        action_files = {}
        
        try:
            action_path = Path(action_dir)
            
            # First, look for action.yml/yaml (most important)
            for action_file in ["action.yml", "action.yaml"]:
                action_yml_path = action_path / action_file
                if action_yml_path.exists():
                    try:
                        with open(action_yml_path, 'r', encoding='utf-8') as f:
                            action_files[action_file] = f.read()
                        logger.debug(f"✅ Found action definition: {action_file}")
                    except Exception as e:
                        logger.warning(f"⚠️  Could not read {action_file}: {e}")
                    break
            
            # Then collect other relevant files
            processed_files = self._process_directory(action_path, action_path)
            action_files.update(processed_files)
            
            logger.info(f"📁 Extracted {len(action_files)} files for analysis")
            
            # Log file summary
            self._log_file_summary(action_files)
            
            return action_files
            
        except Exception as e:
            logger.error(f"❌ Failed to extract action files: {e}")
            return {}
    
    def _process_directory(self, base_path: Path, current_path: Path) -> Dict[str, str]:
        """
        Recursively process directory and extract relevant files.
        
        Args:
            base_path: Base path of the action
            current_path: Current directory being processed
            
        Returns:
            Dictionary of relative file paths to contents
        """
        files = {}
        
        try:
            for item in current_path.iterdir():
                if item.is_file():
                    relative_path = item.relative_to(base_path)
                    
                    if self._should_include_file(item, relative_path):
                        content = self._read_file_safely(item)
                        if content is not None:
                            files[str(relative_path)] = content
                
                elif item.is_dir() and self._should_include_directory(item):
                    # Recursively process subdirectory
                    subdir_files = self._process_directory(base_path, item)
                    files.update(subdir_files)
        
        except Exception as e:
            logger.warning(f"⚠️  Error processing directory {current_path}: {e}")
        
        return files
    
    def _should_include_file(self, file_path: Path, relative_path: Path) -> bool:
        """
        Determine if a file should be included in analysis.
        
        Args:
            file_path: Absolute path to file
            relative_path: Relative path from action root
            
        Returns:
            True if file should be included
        """
        # Always include priority files
        if file_path.name in self.priority_files:
            return True
        
        # Skip if already processed (action.yml/yaml)
        if str(relative_path) in ["action.yml", "action.yaml"]:
            return False
        
        # Skip excluded files
        if file_path.name in self.exclude_files:
            return False
        
        # Skip excluded extensions
        if file_path.suffix.lower() in self.exclude_extensions:
            return False
        
        # Skip files that are too large
        try:
            if file_path.stat().st_size > self.max_file_size:
                logger.debug(f"⏭️  Skipping large file: {relative_path} ({file_path.stat().st_size} bytes)")
                return False
        except OSError:
            return False
        
        # Skip if in excluded directory
        if any(exclude_dir in relative_path.parts for exclude_dir in self.exclude_dirs):
            return False
        
        # Include files with relevant extensions
        relevant_extensions = {
            ".py", ".js", ".ts", ".sh", ".bash", ".ps1", ".yml", ".yaml", 
            ".json", ".xml", ".go", ".rs", ".java", ".c", ".cpp", ".h", 
            ".php", ".rb", ".pl", ".r", ".scala", ".kt", ".swift", ".cs",
            ".dockerfile", ".makefile"
        }
        
        if file_path.suffix.lower() in relevant_extensions:
            return True
        
        # Include files without extension that might be scripts
        if not file_path.suffix and self._is_likely_script(file_path):
            return True
        
        return False
    
    def _should_include_directory(self, dir_path: Path) -> bool:
        """
        Determine if a directory should be processed.
        
        Args:
            dir_path: Path to directory
            
        Returns:
            True if directory should be processed
        """
        return dir_path.name not in self.exclude_dirs
    
    def _is_likely_script(self, file_path: Path) -> bool:
        """
        Check if a file without extension is likely a script.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file is likely a script
        """
        try:
            # Check if file is executable
            if os.access(file_path, os.X_OK):
                return True
            
            # Check first few bytes for shebang
            with open(file_path, 'rb') as f:
                first_bytes = f.read(10)
                if first_bytes.startswith(b'#!'):
                    return True
            
            # Check common script names
            script_names = {
                "entrypoint", "run", "start", "build", "deploy", "setup", 
                "install", "configure", "main", "execute", "launch"
            }
            
            if file_path.name.lower() in script_names:
                return True
            
        except Exception:
            pass
        
        return False
    
    def _read_file_safely(self, file_path: Path) -> Optional[str]:
        """
        Safely read file content with encoding detection.
        
        Args:
            file_path: Path to file
            
        Returns:
            File content as string or None if failed
        """
        encodings = ['utf-8', 'utf-16', 'latin-1', 'ascii']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                    
                    # Skip empty files
                    if not content.strip():
                        return None
                    
                    # Skip binary-like content
                    if self._is_binary_content(content):
                        return None
                    
                    return content
                    
            except (UnicodeDecodeError, PermissionError):
                continue
            except Exception as e:
                logger.debug(f"⚠️  Error reading {file_path}: {e}")
                break
        
        return None
    
    def _is_binary_content(self, content: str) -> bool:
        """
        Check if content appears to be binary.
        
        Args:
            content: File content
            
        Returns:
            True if content appears binary
        """
        # Check for null bytes (common in binary files)
        if '\x00' in content:
            return True
        
        # Check ratio of printable characters
        printable_chars = sum(1 for c in content if c.isprintable() or c.isspace())
        if len(content) > 0 and (printable_chars / len(content)) < 0.7:
            return True
        
        return False
    
    def _log_file_summary(self, action_files: Dict[str, str]):
        """
        Log a summary of extracted files.
        
        Args:
            action_files: Dictionary of extracted files
        """
        if not action_files:
            logger.warning("⚠️  No files extracted for analysis")
            return
        
        # Categorize files by type
        categories = {
            'Action Definition': [],
            'Scripts': [],
            'Source Code': [],
            'Configuration': [],
            'Other': []
        }
        
        for file_path in action_files.keys():
            path_obj = Path(file_path)
            
            if path_obj.name in ['action.yml', 'action.yaml']:
                categories['Action Definition'].append(file_path)
            elif path_obj.suffix in ['.sh', '.bash', '.ps1'] or path_obj.name in ['entrypoint', 'run']:
                categories['Scripts'].append(file_path)
            elif path_obj.suffix in ['.py', '.js', '.ts', '.go', '.rs', '.java', '.c', '.cpp']:
                categories['Source Code'].append(file_path)
            elif path_obj.suffix in ['.yml', '.yaml', '.json', '.xml', '.toml']:
                categories['Configuration'].append(file_path)
            else:
                categories['Other'].append(file_path)
        
        logger.debug("📋 File extraction summary:")
        for category, files in categories.items():
            if files:
                logger.debug(f"  {category}: {len(files)} files")
                for file_path in files[:3]:  # Show first 3 files
                    logger.debug(f"    - {file_path}")
                if len(files) > 3:
                    logger.debug(f"    ... and {len(files) - 3} more")
    
    def validate_extracted_files(self, action_files: Dict[str, str]) -> Dict[str, Any]:
        """
        Validate extracted files and provide analysis metadata.
        
        Args:
            action_files: Dictionary of extracted files
            
        Returns:
            Validation results and metadata
        """
        validation = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'metadata': {
                'total_files': len(action_files),
                'total_size': 0,
                'has_action_definition': False,
                'file_types': {},
                'largest_file': None,
                'largest_file_size': 0
            }
        }
        
        try:
            # Check for action definition
            has_action_def = any(
                filename in ['action.yml', 'action.yaml'] 
                for filename in action_files.keys()
            )
            validation['metadata']['has_action_definition'] = has_action_def
            
            if not has_action_def:
                validation['warnings'].append("No action.yml or action.yaml found")
            
            # Analyze file types and sizes
            for filename, content in action_files.items():
                file_size = len(content.encode('utf-8'))
                validation['metadata']['total_size'] += file_size
                
                # Track largest file
                if file_size > validation['metadata']['largest_file_size']:
                    validation['metadata']['largest_file'] = filename
                    validation['metadata']['largest_file_size'] = file_size
                
                # Count file types
                ext = Path(filename).suffix.lower()
                if ext:
                    validation['metadata']['file_types'][ext] = validation['metadata']['file_types'].get(ext, 0) + 1
                else:
                    validation['metadata']['file_types']['no_extension'] = validation['metadata']['file_types'].get('no_extension', 0) + 1
            
            # Check if we have enough content for analysis
            if validation['metadata']['total_size'] < 100:  # Less than 100 bytes
                validation['warnings'].append("Very little content extracted for analysis")
            
            # Check for suspicious patterns
            self._check_suspicious_patterns(action_files, validation)
            
        except Exception as e:
            validation['valid'] = False
            validation['errors'].append(f"Validation failed: {e}")
        
        return validation
    
    def _check_suspicious_patterns(self, action_files: Dict[str, str], validation: Dict[str, Any]):
        """
        Check for suspicious patterns in extracted files.
        
        Args:
            action_files: Dictionary of extracted files
            validation: Validation dictionary to update
        """
        suspicious_patterns = [
            'eval(', 'exec(', 'system(', 'shell_exec(', 'passthru(',
            'curl -s', 'wget -q', 'base64 -d', 'echo $',
            'rm -rf', 'chmod +x', '/tmp/', '/dev/null'
        ]
        
        for filename, content in action_files.items():
            content_lower = content.lower()
            
            for pattern in suspicious_patterns:
                if pattern in content_lower:
                    validation['warnings'].append(
                        f"Suspicious pattern '{pattern}' found in {filename}"
                    )
    
    def prepare_for_analysis(self, action_files: Dict[str, str]) -> Dict[str, str]:
        """
        Prepare extracted files for AI analysis by cleaning and formatting.
        
        Args:
            action_files: Dictionary of extracted files
            
        Returns:
            Cleaned and prepared files for analysis
        """
        prepared_files = {}
        
        for filename, content in action_files.items():
            # Clean content
            cleaned_content = self._clean_file_content(content)
            
            # Add file metadata as comment
            file_info = f"# File: {filename}\n# Size: {len(content)} characters\n\n"
            prepared_files[filename] = file_info + cleaned_content
        
        return prepared_files
    
    def _clean_file_content(self, content: str) -> str:
        """
        Clean file content for analysis.
        
        Args:
            content: Raw file content
            
        Returns:
            Cleaned content
        """
        # Remove excessive whitespace
        lines = content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Remove trailing whitespace
            cleaned_line = line.rstrip()
            cleaned_lines.append(cleaned_line)
        
        # Remove excessive empty lines (more than 2 consecutive)
        final_lines = []
        empty_count = 0
        
        for line in cleaned_lines:
            if line.strip() == '':
                empty_count += 1
                if empty_count <= 2:
                    final_lines.append(line)
            else:
                empty_count = 0
                final_lines.append(line)
        
        return '\n'.join(final_lines)


# Factory function for easy processor creation
def create_file_processor(max_file_size: int = 512 * 1024) -> FileProcessor:
    """
    Factory function to create a file processor.
    
    Args:
        max_file_size: Maximum file size to process (in bytes)
        
    Returns:
        Configured FileProcessor instance
    """
    return FileProcessor(max_file_size)
