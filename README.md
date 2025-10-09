# ActionsGuardHub

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

A comprehensive, **modular** security analysis tool for GitHub Actions that provides AI-powered analysis for malicious github actions, vulnerability detection, detailed reporting, and an intuitive web dashboard for results visualization.

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Google Gemini API key (for AI analysis)
- GitHub authentication (recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/suchithnarayan/ai-gha-scan.git
   cd ai-gha-scan
   ```

2. **Set up virtual environment** (recommended)
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   # Full installation (all AI providers)
   pip install -r requirements.txt
   
   # Minimal installation (Gemini only)
   pip install requests PyJWT cryptography PyYAML backoff json-repair python-dotenv langchain-core langchain-google-genai
   
   # Verify installation
   python verify_dependencies.py
   ```

4. **Set up environment variables**
   ```bash
   # Copy example environment file
   cp env.example .env  # Create this if it doesn't exist
   
   # Edit .env with your API keys
   export GOOGLE_API_KEY="your_google_api_key"     # For Gemini models (default)
   export OPENAI_API_KEY="your_openai_api_key"     # For OpenAI models (optional)
   export GITHUB_PAT_TOKEN="your_github_token"     # Optional but recommended
   ```

### Basic Usage

```bash
# Scan a single action
python actionsguardhub.py --input-type actions --input-value "actions/checkout@v4"

# Scan multiple actions
python actionsguardhub.py --input-type actions --input-value "actions/checkout@v4,actions/setup-node@v3"

# Scan all actions in a repository
python actionsguardhub.py --input-type repositories --input-value "microsoft/vscode"

# Scan entire organization
python actionsguardhub.py --input-type organization --input-value "microsoft"

# Use OpenAI instead of Gemini
python actionsguardhub.py --ai-model openai --model-name gpt-4o-mini --input-value "actions/checkout@v4"

# Metadata collection only (no AI analysis)
python actionsguardhub.py --skip-ai-scan --input-type repositories --input-value "actions/checkout"
```

### UI Usage

```bash
# Start a python server in the project root
python -m http.server 
```

## 🌟 Features

### 🔍 **Comprehensive Security Analysis**
- **LangChain-Powered AI**: Multiple AI provider support through LangChain framework
- **Multi-Model Support**: Google Gemini, OpenAI GPT, and easily extensible for others
- **10+ Security Categories**: Entry points, network calls, secrets exposure, file system risks, and more
- **Severity Classification**: Critical, High, Medium, and Low severity issues
- **Detailed Recommendations**: Actionable mitigation strategies for identified issues

> ⚠️ **Important**: This tool uses AI models which may produce false positives or miss actual vulnerabilities. Always have security experts review AI-generated findings. See [Disclaimers & Limitations](#️-important-disclaimers--limitations) for details.

### 📊 **Flexible Input Methods**
- **Single Actions**: Analyze individual GitHub Actions
- **Multiple Actions**: Batch analysis with comma-separated lists or files
- **Repository Scanning**: Analyze all actions used in a repository
- **Organization Scanning**: Comprehensive analysis across entire organizations

### 🔐 **Multiple Authentication Options**
- **Personal Access Token**: Good rate limits (5,000 requests/hour) - **Default and recommended for most users**
- **GitHub App**: Highest rate limits (15,000 requests/hour) - Best for organizations
- **No Authentication**: Limited rate limits (60 requests/hour) - For testing only

### 📋 **Rich Reporting**
- **Human-Readable Reports**: Detailed text reports for each action
- **Batch Summaries**: Aggregate analysis across multiple actions
- **Web Dashboard**: Interactive visualization of results
- **JSON Export**: Machine-readable format for integration

### 🏗️ **Modular Architecture** *(New!)*
- **Extensible AI Models**: Easy to add new AI providers
- **Pluggable Components**: GitHub client, file processors, report generators
- **Clean Separation**: Each module has a single responsibility
- **Developer Friendly**: Well-documented, testable, and maintainable code

## 📖 Documentation

### Authentication Setup

#### Option 1: Personal Access Token (Default and Recommended)

1. Generate a PAT at [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
2. Grant `public_repo` scope for public repositories
3. Set environment variable:
   ```bash
   export GITHUB_PAT_TOKEN="your_token_here"
   ```

#### Option 2: GitHub App (For organizations)

1. Create a GitHub App at [GitHub Settings > Developer settings > GitHub Apps](https://github.com/settings/apps)
2. Generate and download the private key
3. Install the app on your organization
4. Set environment variables:
   ```bash
   export GITHUB_APP_CLIENT_ID="your_client_id"
   export GITHUB_APP_PRIVATE_KEY="your_private_key"
   export GITHUB_APP_INSTALLATION_ID="your_installation_id"
   ```

### Command Line Options

```bash
python actionsguardhub.py [OPTIONS]

Input Options:
  --input-type {actions,repositories,organization}
                        Type of input to process (default: actions)
  --input-value INPUT_VALUE
                        Input value: action reference, repository, or organization
  --input-file INPUT_FILE
                        File containing list of actions

Authentication Options:
  --auth-type {github_app,pat_token,no_auth}
                        Authentication method (default: pat_token)
  --github-pat-token TOKEN
                        GitHub Personal Access Token

Output Options:
  --output-dir DIR      Output directory for scan results
  --reports-dir DIR     Directory for human-readable reports
  --skip-ai-scan        Skip AI analysis and collect metadata only
  --verbose, -v         Enable verbose logging

AI Model Options:
  --ai-model {gemini,openai}
                        AI model provider to use (default: gemini)
  --model-name MODEL_NAME
                        Specific model name (e.g., gemini-2.5-pro, gpt-4o-mini)
```

### 🤖 AI Model Configuration

The scanner uses **LangChain** for AI model management, supporting multiple providers:

#### Available Models

| Provider | Models | Environment Variable | Installation |
|----------|--------|---------------------|--------------|
| **Google Gemini** | `gemini-2.5-flash` (recommended), `gemini-2.5-pro` | `GOOGLE_API_KEY` | `pip install langchain-google-genai` |
| **OpenAI** | `gpt-4o-mini` (recommended), `gpt-4o`, `gpt-3.5-turbo`, `o1-mini` | `OPENAI_API_KEY` | `pip install langchain-openai` |

#### Usage Examples

```bash
# Use default Gemini model
python actionsguardhub.py --input-value "actions/checkout@v4"

# Use specific Gemini model
python actionsguardhub.py --ai-model gemini --model-name gemini-2.5-flash --input-value "actions/checkout@v4"

# Use OpenAI model
python actionsguardhub.py --ai-model openai --model-name gpt-4o-mini --input-value "actions/checkout@v4"
```

#### Cost Configuration

AI model costs are **completely configuration-driven** in `ai_model_costs.json`. No code changes needed for pricing updates!

**Supported Pricing Types:**

1. **Simple Pricing** (fixed rates):
```json
{
  "provider": {
    "models": {
      "model-name": {
        "pricing_type": "simple",
        "input_cost_per_million": 1.25,
        "output_cost_per_million": 10.00,
        "context_cost_per_million": 0.31
      }
    }
  }
}
```

2. **Tiered Pricing** (rates change based on usage):
```json
{
  "gemini": {
    "models": {
      "gemini-2.5-pro": {
        "pricing_type": "tiered_by_total_tokens",
        "tiers": [
          {
            "threshold": 200000,
            "condition": "<=",
            "input_cost_per_million": 1.25,
            "output_cost_per_million": 10.00
          },
          {
            "threshold": 200000,
            "condition": ">",
            "input_cost_per_million": 2.50,
            "output_cost_per_million": 15.00
          }
        ]
      }
    }
  }
}
```

**Available Pricing Types:**
- `simple`: Fixed cost per million tokens
- `tiered_by_total_tokens`: Different rates based on total token count
- `tiered_by_input_tokens`: Different rates based on input token count  
- `tiered_by_output_tokens`: Different rates based on output token count

**Adding New Models:** Just update the JSON file - no code changes required!

> ⚠️ **Important**: Gemini pricing has increased significantly. For cost optimization:
> - Use **Gemini 2.5 Flash** for most use cases (much cheaper)
> - Monitor your usage costs carefully
> - Consider OpenAI GPT-4o-mini for very cost-sensitive applications

## 📊 Understanding Results

### Security Report Structure

Each scanned action generates a comprehensive report including:

1. **Basic Information** - Action name, version, repository stats
2. **Security Analysis Summary** - Safety scores and issue counts
3. **Detailed Security Checks** - 10+ security categories with analysis
4. **Security Issues** - Detailed findings with severity levels
5. **Recommendations** - Actionable mitigation strategies

### Web Dashboard

Open `frontend/index.html` in your browser to access the interactive dashboard with:
- Overview statistics and trends
- Action details and security scores
- Search and filtering capabilities
- Export functionality

### Report Files

```
scan-reports/                    # Human-readable text reports
├── actions-checkout_v4_20241005_094453.txt
└── batch_scan_20241005_094923.txt

frontend/output/              # JSON scan results (for dashboard)
├── actions-checkout@v4.json
└── security-overview.json

frontend/output-metadata/       # Scan metadata (tokens, cost)
└── actions-checkout_v4-metadata.txt

frontend/action-stats.json     # Repository statistics
```



#### **✅ Good Use Cases**
- Initial security screening of third-party actions
- Bulk analysis of large action repositories
- Educational purposes and security awareness
- Supplementing existing security review processes
- Identifying potential areas for deeper manual review

#### **❌ Inappropriate Use Cases**
- Sole security validation for production systems
- Compliance certification without human review
- High-stakes security decisions without verification
- Replacing comprehensive security audits
- Legal or regulatory compliance as primary evidence


---

**Remember: AI-powered security analysis is a powerful tool to augment human expertise, not replace it. Always combine AI insights with human judgment and comprehensive security practices.**

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
git clone https://github.com/YOUR_USERNAME/ai-gha-scan.git
cd ai-gha-scan

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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support & Community

- **Issues**: [GitHub Issues](https://github.com/suchithnarayan/ai-gha-scan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/suchithnarayan/ai-gha-scan/discussions)
- **Documentation**: This README and inline code documentation
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines


## ⚠️ Important Disclaimers & Limitations

### 🤖 AI Model Limitations

**This tool uses AI models for security analysis. Please be aware of the following important limitations:**

#### **False Positives & False Negatives**
- ✅ **False Positives**: AI models may flag legitimate code as potentially malicious or vulnerable
- ❌ **False Negatives**: AI models may miss actual security vulnerabilities or malicious code
- 🔍 **Human Review Required**: Always have security experts review AI-generated findings

#### **Model-Specific Considerations**
- **Google Gemini**: May have different detection patterns and biases than other models
- **OpenAI GPT**: Training data cutoffs may affect detection of newer attack patterns
- **Anthropic Claude**: Different reasoning approaches may yield varying results
- **Model Updates**: AI model behavior can change with provider updates

#### **Context & Accuracy**
- 🎯 **Context Dependency**: AI analysis quality depends on the completeness of provided code context
- 📊 **Probabilistic Nature**: AI provides probability-based assessments, not definitive security guarantees
- 🔄 **Consistency**: Same code may receive different analysis results across multiple runs
- 🧠 **Training Limitations**: Models are limited by their training data and may not recognize novel attack vectors

### 🛡️ Security Analysis Scope

#### **What This Tool Analyzes**
- ✅ Static code analysis of GitHub Action files
- ✅ Common vulnerability patterns and suspicious code structures
- ✅ Potential security risks in workflow configurations
- ✅ Best practice violations and configuration issues

#### **What This Tool Does NOT Analyze**
- ❌ **Runtime Behavior**: Cannot detect runtime-only vulnerabilities
- ❌ **Dynamic Analysis**: No execution-time security testing
- ❌ **Network Security**: Limited analysis of network-based threats
- ❌ **Infrastructure Security**: Does not assess underlying infrastructure
- ❌ **Dependency Vulnerabilities**: Does not perform deep dependency scanning

### 📋 Best Practices for Using AI Security Analysis

#### **Recommended Workflow**
1. **🔍 Use as Initial Screening**: Treat AI analysis as a first-pass security review
2. **👥 Human Verification**: Always have security professionals review flagged issues
3. **🔄 Multiple Models**: Consider using different AI providers for cross-validation
4. **📊 Trend Analysis**: Look for patterns across multiple scans rather than single results
5. **🛠️ Combine with Other Tools**: Integrate with traditional security scanning tools

#### **Risk Mitigation**
- **🚨 Critical Systems**: Never rely solely on AI analysis for critical security decisions
- **📝 Documentation**: Document all AI findings and human review decisions
- **🔄 Regular Updates**: Re-scan actions periodically as AI models improve
- **🎯 Targeted Review**: Focus human review on high-risk areas identified by AI

### 🎯 Appropriate Use Cases

---

**Made with ❤️ for the GitHub Actions security community**

*Star ⭐ this repository if you find it useful!*