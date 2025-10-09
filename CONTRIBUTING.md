# Contributing to GitHub Actions Security Scanner

Thank you for your interest in contributing to the GitHub Actions Security Scanner! This document provides comprehensive guidelines for contributing to our open-source project.

## 🎯 Project Vision

Our goal is to create the most comprehensive, extensible, and user-friendly security scanner for GitHub Actions. We believe in:

- **Modularity**: Clean, separated components that are easy to understand and extend
- **Extensibility**: Support for multiple AI models, authentication methods, and output formats
- **Quality**: Well-tested, documented, and maintainable code
- **Community**: Welcoming environment for contributors of all skill levels

## 🏗️ Architecture Overview

Understanding our modular architecture will help you contribute effectively:

### Core Modules

```
├── 🧠 scanner_core.py              # Main orchestration & workflow
├── 🐙 github_client.py             # GitHub API interactions
├── 🤖 ai_core.py                   # AI model management
├── 📁 file_processor.py            # File extraction & processing
├── 📊 report_generator.py          # Report generation
├── 🔐 github_auth.py               # Authentication management
└── 📥 input_manager.py             # Input processing
```

### Design Principles

1. **Single Responsibility**: Each module has one clear purpose
2. **Dependency Injection**: Components are injected rather than hard-coded
3. **Interface Segregation**: Clean interfaces for extensibility
4. **Error Handling**: Graceful degradation and comprehensive logging
5. **Type Safety**: Full type hints for better IDE support and catching errors

## 🚀 Getting Started

### Development Environment Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ai-gha-scan.git
   cd ai-gha-scan
   ```

2. **Set Up Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   # Core dependencies
   pip install -r requirements.txt
   
   # Development dependencies
   pip install pytest pytest-cov black isort flake8 mypy pre-commit
   ```

4. **Set Up Pre-commit Hooks** (Optional but recommended)
   ```bash
   pre-commit install
   ```

5. **Test Installation**
   ```bash
   python -c "
   from github_client import GitHubClient
   from ai_core import create_ai_core
   from file_processor import create_file_processor
   print('✅ Development environment ready!')
   "
   ```

### Environment Variables

Create a `.env` file for development:

```bash
# AI Model API Keys (choose your provider)
GOOGLE_API_KEY=your_google_api_key        # For Gemini models (default)
OPENAI_API_KEY=your_openai_api_key        # For OpenAI models (optional)

# GitHub authentication (recommended for development)
GITHUB_PAT_TOKEN=your_personal_access_token

# Development settings
GHA_SCANNER_DEBUG=true
GHA_SCANNER_LOG_LEVEL=DEBUG
```

## 📝 Contribution Types

We welcome various types of contributions:

### 🐛 Bug Reports

When reporting bugs, please include:

- **Environment**: Python version, OS, dependencies
- **Steps to Reproduce**: Clear, minimal reproduction steps
- **Expected vs Actual**: What you expected vs what happened
- **Logs**: Relevant error messages and stack traces
- **Context**: What you were trying to accomplish

**Template:**
```markdown
## Bug Description
Brief description of the issue

## Environment
- Python version: 3.x.x
- OS: macOS/Linux/Windows
- Scanner version: x.x.x

## Steps to Reproduce
1. Run command: `python actionsguardhub.py ...`
2. Expected: X should happen
3. Actual: Y happened instead

## Error Logs
```
Paste error logs here
```

## Additional Context
Any other relevant information
```

### ✨ Feature Requests

For new features, please provide:

- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Implementation**: Rough implementation plan (if you have ideas)

### 🔧 Code Contributions

We especially welcome contributions in these areas:

#### High Priority
- **New AI Model Support**: OpenAI GPT, Claude, local models
- **Enhanced Security Checks**: New vulnerability patterns
- **Performance Improvements**: Caching, parallel processing
- **Test Coverage**: Unit tests, integration tests

#### Medium Priority
- **Documentation**: Code comments, examples, tutorials
- **UI/UX Improvements**: Web dashboard enhancements
- **Output Formats**: SARIF, CSV, XML export
- **GitHub Integration**: GitHub Apps, Actions integration

#### Low Priority
- **Code Quality**: Refactoring, optimization
- **Developer Experience**: Better error messages, debugging tools

## 🧩 Adding New Features

### Adding a New AI Model (LangChain-based)

The scanner now uses **LangChain** for AI model integration. Here's how to add a new provider:

1. **Install LangChain Package**
   ```bash
   pip install langchain-anthropic  # Example for Anthropic
   ```

2. **Implement LangChain Model Class**
   ```python
   # In ai_core.py
   class LangChainAnthropicModel(AIModelInterface):
       def __init__(self, model: str = "claude-3-haiku", api_key: Optional[str] = None, **kwargs):
           if not HAS_LANGCHAIN_ANTHROPIC:
               raise ImportError("langchain-anthropic is required")
           
           self.model_name = model
           self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
           
           self.llm = ChatAnthropic(
               model=model,
               api_key=self.api_key,
               **kwargs
           )
           self.cost_calculator = CostCalculator()
       
       def analyze_security(self, prompt: str, action_files: Dict[str, str]) -> Dict[str, Any]:
           messages = [("system", "Security expert prompt"), ("human", full_prompt)]
           response = self.llm.invoke(messages)
           # Process response and return results
   ```

3. **Update Factory Function**
   ```python
   def _create_model(self, model_type: str, model_name: Optional[str], **config):
       elif model_type == "anthropic":
           default_model = model_name or "claude-3-haiku"
           return LangChainAnthropicModel(model=default_model, **config)
   ```

4. **Add Cost Configuration** (No code changes needed!)
   ```json
   // In ai_model_costs.json - just add your model configuration
   {
     "anthropic": {
       "models": {
         "claude-3-haiku": {
           "pricing_type": "simple",
           "input_cost_per_million": 0.25,
           "output_cost_per_million": 1.25
         },
         "claude-3-5-sonnet": {
           "pricing_type": "tiered_by_total_tokens",
           "tiers": [
             {
               "threshold": 100000,
               "condition": "<=",
               "input_cost_per_million": 3.00,
               "output_cost_per_million": 15.00
             },
             {
               "threshold": 100000,
               "condition": ">",
               "input_cost_per_million": 6.00,
               "output_cost_per_million": 30.00
             }
           ]
         }
       }
     }
   }
   ```

5. **Update CLI Options**
   ```python
   # In actionsguardhub.py
   choices=['gemini', 'openai', 'anthropic']
   ```

3. **Add Tests**
   ```python
   # tests/test_ai_core.py
   def test_your_ai_model():
       model = YourAIModel(api_key="test")
       result = model.analyze_security("test prompt", {"test.py": "print('hello')"})
       assert result['success'] is True
   ```

4. **Update Documentation**
   - Add usage example to README
   - Document configuration options
   - Add to supported models list

### Adding GitHub API Features

1. **Extend GitHubClient**
   ```python
   # In github_client.py
   class GitHubClient:
       def get_security_advisories(self, owner: str, repo: str) -> List[Dict]:
           """Get security advisories for a repository."""
           url = f"{self.api_base}/repos/{owner}/{repo}/security-advisories"
           response = self.make_request(url)
           return response.json() if response else []
   ```

2. **Add Error Handling**
```python
   def get_security_advisories(self, owner: str, repo: str) -> List[Dict]:
       try:
           url = f"{self.api_base}/repos/{owner}/{repo}/security-advisories"
           response = self.make_request(url)
           if response and response.status_code == 200:
               return response.json()
           return []
       except Exception as e:
           logger.error(f"Failed to get security advisories for {owner}/{repo}: {e}")
           return []
   ```

3. **Update Scanner Core**
   ```python
   # In scanner_core.py - use the new feature
   def _collect_security_info(self, owner: str, repo: str):
       advisories = self.github_client.get_security_advisories(owner, repo)
       # Process advisories...
   ```

### Adding File Processing Features

1. **Extend FileProcessor**
   ```python
   # In file_processor.py
   class FileProcessor:
       def detect_secrets(self, content: str) -> List[Dict]:
           """Detect potential secrets in file content."""
           secrets = []
           # Implement secret detection logic
           return secrets
   ```

2. **Integrate with Validation**
   ```python
   def validate_extracted_files(self, action_files: Dict[str, str]) -> Dict[str, Any]:
       validation = super().validate_extracted_files(action_files)
       
       # Add secret detection
       for filename, content in action_files.items():
           secrets = self.detect_secrets(content)
           if secrets:
               validation['warnings'].append(f"Potential secrets found in {filename}")
       
       return validation
   ```

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_ai_core.py

# Run with verbose output
pytest -v

# Run only failed tests
pytest --lf
```

### Writing Tests

1. **Unit Tests**: Test individual functions and methods
   ```python
   def test_parse_action_reference():
       client = GitHubClient(mock_auth)
       owner, repo, version = client.parse_action_reference("actions/checkout@v4")
       assert owner == "actions"
       assert repo == "checkout"
       assert version == "v4"
   ```

2. **Integration Tests**: Test component interactions
   ```python
   def test_scanner_workflow():
       scanner = GitHubActionsScanner(test_config, mock_auth)
       result = scanner.scan_action("actions/checkout@v4", skip_ai_scan=True)
       assert result['success'] is True
   ```

3. **Mock External Dependencies**
   ```python
   @patch('requests.get')
   def test_github_api_call(mock_get):
       mock_get.return_value.json.return_value = {"name": "test"}
       client = GitHubClient(mock_auth)
       result = client.get_repository_info("owner", "repo")
       assert result["name"] == "test"
```

### Test Structure

```
tests/
├── conftest.py                 # Pytest configuration and fixtures
├── test_github_client.py       # GitHub client tests
├── test_ai_core.py             # AI core tests
├── test_file_processor.py      # File processor tests
├── test_scanner_core.py        # Scanner core tests
├── integration/                # Integration tests
│   ├── test_full_workflow.py
│   └── test_api_integration.py
└── fixtures/                   # Test data
    ├── sample_actions/
    └── mock_responses/
```

## 📋 Code Style Guidelines

### Python Style

We follow **PEP 8** with some modifications:

```python
# Line length: 100 characters (not 79)
# Use double quotes for strings
# Use type hints for all function parameters and returns

def process_action(action_ref: str, config: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Process a GitHub action reference.
    
    Args:
        action_ref: GitHub action reference (e.g., "actions/checkout@v4")
        config: Configuration dictionary
        
    Returns:
        Processing result or None if failed
    """
    pass
```

### Documentation Style

1. **Docstrings**: Use Google-style docstrings
   ```python
   def complex_function(param1: str, param2: int = 10) -> Dict[str, Any]:
       """
       Brief description of the function.
       
       Longer description if needed. Explain the purpose, behavior,
       and any important details.
       
       Args:
           param1: Description of param1
           param2: Description of param2 with default value
           
       Returns:
           Description of return value
           
       Raises:
           ValueError: When param1 is invalid
           RuntimeError: When operation fails
           
       Example:
           >>> result = complex_function("test", 20)
           >>> print(result["status"])
           "success"
       """
   ```

2. **Comments**: Explain why, not what
   ```python
   # Good: Explain the reasoning
   # Use exponential backoff to handle rate limiting gracefully
   @backoff.on_exception(backoff.expo, requests.RequestException, max_tries=3)
   
   # Bad: Explain what the code does
   # This function makes a request
   ```

3. **Type Hints**: Use comprehensive type hints
   ```python
   from typing import Dict, List, Optional, Union, Any, Tuple
   
   def process_files(files: Dict[str, str]) -> Tuple[bool, List[str]]:
       """Process files and return success status and error messages."""
       pass
   ```

### Code Formatting

Use these tools to maintain consistent formatting:

   ```bash
# Format code
black . --line-length 100

# Sort imports
isort . --profile black

# Check style
flake8 . --max-line-length 100 --extend-ignore E203,W503

# Type checking
mypy . --ignore-missing-imports
```

### Pre-commit Configuration

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        args: [--line-length=100]
  
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: [--profile=black]
  
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=100, --extend-ignore=E203,W503]
```

## 🔄 Pull Request Process

### Before Submitting

1. **Test Your Changes**
   ```bash
   # Run tests
   pytest
   
   # Check formatting
   black . --check
   isort . --check-only
   flake8 .
   
   # Test basic functionality
   python actionsguardhub.py --help
   ```

2. **Update Documentation**
   - Update README if adding new features
   - Add docstrings to new functions
   - Update type hints

3. **Add Tests**
   - Unit tests for new functions
   - Integration tests for new workflows
   - Update existing tests if needed

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings or errors
```

### Review Process

1. **Automated Checks**: CI will run tests and style checks
2. **Code Review**: Maintainers will review your code
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, your PR will be merged

## 🏷️ Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `actionsguardhub.py`
2. Update CHANGELOG.md
3. Create release notes
4. Tag the release
5. Update documentation

## 🤝 Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- **Be respectful** in all interactions
- **Be constructive** when providing feedback
- **Be patient** with new contributors
- **Be collaborative** in problem-solving

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: General questions, ideas
- **Pull Requests**: Code contributions
- **Code Reviews**: Constructive feedback

### Recognition

Contributors will be recognized in:
- README contributors section
- Release notes
- GitHub contributors page

## 📚 Resources

### Learning Resources

- **Python Best Practices**: [Real Python](https://realpython.com/)
- **GitHub API**: [GitHub REST API Documentation](https://docs.github.com/en/rest)
- **AI/ML APIs**: [Google Gemini](https://ai.google.dev/), [OpenAI](https://platform.openai.com/docs)
- **Testing**: [pytest Documentation](https://docs.pytest.org/)

### Project-Specific Resources

- **Architecture Decisions**: See `docs/architecture/` (if exists)
- **API Documentation**: Generated from docstrings
- **Examples**: See `examples/` directory (if exists)

## ❓ Getting Help

### Before Asking for Help

1. Check existing issues and discussions
2. Read the documentation thoroughly
3. Try debugging with verbose logging (`--verbose`)

### How to Ask for Help

1. **Be Specific**: Describe exactly what you're trying to do
2. **Provide Context**: Include relevant code, error messages, environment details
3. **Show Effort**: Explain what you've already tried
4. **Be Patient**: Maintainers are volunteers with limited time

### Where to Get Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general help
- **Code Comments**: For understanding specific implementations

---

Thank you for contributing to the GitHub Actions Security Scanner! Your contributions help make the GitHub Actions ecosystem more secure for everyone. 🙏

**Happy coding!** 🚀