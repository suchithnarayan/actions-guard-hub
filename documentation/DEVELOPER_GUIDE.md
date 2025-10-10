## 🛠️ Developer Guide

### Adding New AI Models

The LangChain-based architecture makes adding new AI providers straightforward:

```python
# 1. Install LangChain package
pip install langchain-anthropic  # Example for Anthropic

# 2. Add model class to ai_core.py
class LangChainAnthropicModel(AIModelInterface):
    def __init__(self, model="claude-3-haiku", **kwargs):
        self.llm = ChatAnthropic(model=model, **kwargs)

# 3. Update factory function
def _create_model(self, model_type, model_name, **config):
    elif model_type == "anthropic":
        return LangChainAnthropicModel(model=model_name or "claude-3-haiku", **config)

# 4. Add cost config to ai_model_costs.json
{
  "anthropic": {
    "models": {
      "claude-3-haiku": {
        "input_cost_per_million": 0.25,
        "output_cost_per_million": 1.25
      }
    }
  }
}

# 5. Update CLI choices
choices=['gemini', 'openai', 'anthropic']
```

### File Organization

- **Core Logic**: `scanner_core.py` orchestrates everything
- **AI Models**: `ai_core.py` handles all AI provider interactions
- **GitHub API**: `github_client.py` manages all GitHub operations
- **File Processing**: `file_processor.py` handles action file extraction
- **Configuration**: `ai_model_costs.json` for cost calculation

## 🤝 Contributing

We welcome contributions! This project is designed to be **developer-friendly** and **easily extensible**.

### 🚀 Quick Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/suchithnarayan/actions-guard-hub.git
cd actions-guard-hub

# 2. Set up development environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install development dependencies (optional)
pip install pytest pytest-cov black isort flake8 mypy

# 5. Test the installation
python -c "
from github_client import GitHubClient
from ai_core import create_ai_core
from file_processor import create_file_processor
print('✅ All modules imported successfully!')
"
```

### 🧩 Adding New Features

#### Adding a New AI Model

```python
# 1. Create a new model class in ai_core.py
class OpenAIModel(AIModelInterface):
    def analyze_security(self, prompt, files):
        # Your OpenAI implementation
        pass
    
    def validate_json(self, content):
        # Your JSON validation logic
        pass

# 2. Update the factory function
def _create_model(self, model_type, **config):
    if model_type.lower() == "openai":
        return OpenAIModel(**config)
    # ... existing models
```

#### Extending GitHub Features

```python
# Add new methods to github_client.py
class GitHubClient:
    def get_security_advisories(self, owner, repo):
        """Get security advisories for a repository."""
        # Implementation here
        pass
    
    def get_workflow_runs(self, owner, repo):
        """Get recent workflow runs."""
        # Implementation here
        pass
```

#### Custom File Processing

```python
# Extend file_processor.py
class CustomFileProcessor(FileProcessor):
    def __init__(self):
        super().__init__()
        # Add custom file types
        self.priority_files.add("custom-config.yml")
        self.exclude_extensions.remove(".toml")  # Include TOML files
```

### 🧪 Testing

```bash
# Run basic functionality test
python -c "
import sys
sys.path.append('.')
from scanner_core import GitHubActionsScanner
from github_auth import GitHubAuthManager, AuthType

# Test initialization
auth = GitHubAuthManager(AuthType.NO_AUTH)
config = {'output_dir': 'test', 'metadata_dir': 'test', 'reports_dir': 'test', 'stats_file': 'test.json'}
scanner = GitHubActionsScanner(config, auth)
print('✅ Scanner initialized successfully!')
"

# Run with pytest (if installed)
pytest tests/ -v

# Code formatting
black . --check
isort . --check-only
```

### 📋 Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Follow** the existing code style and architecture
4. **Add** tests for new functionality
5. **Update** documentation as needed
6. **Commit** your changes (`git commit -m 'Add amazing feature'`)
7. **Push** to the branch (`git push origin feature/amazing-feature`)
8. **Open** a Pull Request

### 🐛 Reporting Issues

When reporting issues, please include:
- Python version and OS
- Complete error messages and stack traces
- Steps to reproduce the issue
- Expected vs actual behavior

### 💡 Feature Requests

We're always looking for new ideas! Please open an issue with:
- Clear description of the feature
- Use cases and benefits
- Possible implementation approach

## 🔧 Troubleshooting

### Dependency Issues

If you encounter import errors or missing packages:

```bash
# Verify all dependencies
python verify_dependencies.py

# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall

# Install specific AI provider
pip install langchain-openai      # For OpenAI models
pip install langchain-anthropic   # For Anthropic models
```

### Common Issues

#### "No module named 'langchain_openai'"
```bash
pip install langchain-openai
```

#### "No module named 'json_repair'"
```bash
pip install json-repair
```

#### "API key not found" errors
Make sure your environment variables are set:
```bash
export GOOGLE_API_KEY="your_key_here"
export OPENAI_API_KEY="your_key_here"
export GITHUB_PAT_TOKEN="your_token_here"
```

#### Virtual environment issues
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🔧 Advanced Configuration

### Environment Variables

```bash
# AI Model API Keys (choose your provider)
GOOGLE_API_KEY=your_google_api_key        # For Gemini models (default)
OPENAI_API_KEY=your_openai_api_key        # For OpenAI models (optional)

# GitHub authentication (choose one)
GITHUB_PAT_TOKEN=your_personal_access_token
# OR
GITHUB_APP_CLIENT_ID=your_app_client_id
GITHUB_APP_PRIVATE_KEY=your_app_private_key
GITHUB_APP_INSTALLATION_ID=your_installation_id

# Optional: Custom configuration
GHA_SCANNER_OUTPUT_DIR=custom_output
GHA_SCANNER_REPORTS_DIR=custom_reports
```

### Custom Prompt

You can customize the security analysis prompt by editing `prompt.txt` or specifying a custom file:

```bash
python actionsguardhub.py --prompt-file custom_prompt.txt --input-value "actions/checkout@v4"
```

## 📈 Performance & Scaling

- **Rate Limiting**: Automatic handling with exponential backoff
- **Caching**: Intelligent metadata caching (6-hour default)
- **Batch Processing**: Efficient handling of multiple actions
- **Memory Management**: Streaming file processing for large actions

## 🔒 Security & Privacy

- **No Data Storage**: Analysis results are stored locally only
- **API Key Security**: Keys are never logged or transmitted unnecessarily
- **Rate Limiting**: Respects GitHub API limits
- **Error Handling**: Graceful degradation on API failures