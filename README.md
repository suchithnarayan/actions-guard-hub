# ActionsGuardHub

A comprehensive, **modular** security analysis tool for GitHub Actions that provides AI-powered analysis for malicious github actions, vulnerability detection, detailed reporting, and an intuitive web dashboard for results visualization.

## 🖥️ Demo

![ActionsGuardHub Demo](media/overview-AGH.gif)

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Google Gemini API key (for AI analysis)
- GitHub authentication (recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/suchithnarayan/actions-guard-hub.git
   cd actions-guard-hub
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

## 🌟 [Features](documentation/FEATURES.md)

ActionsGuardHub provides comprehensive AI-powered security analysis for GitHub Actions with multiple input methods, flexible authentication options, and rich reporting capabilities. The tool features a modular architecture that supports various AI models through LangChain, analyzes 10+ security categories, and generates actionable recommendations. Developers can read more about detailed features in the [documentation](documentation/FEATURES.md).


> ⚠️ **Important**: This tool uses AI models which may produce false positives or miss actual vulnerabilities. Always have security experts review AI-generated findings. See [Disclaimers & Limitations](documentation/DESCLAIMER.md) for details.

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

### 📊 Understanding Results

Each scan generates comprehensive security reports including basic information, security analysis summaries, detailed security checks across 10+ categories, and actionable recommendations. Results are available through an interactive web dashboard with filtering capabilities and can be exported in multiple formats (JSON, text reports). Read more in the [documentation](documentation/UNDERSTANDING_RESULTS.md).

### 🎯 Appropriate Use Cases

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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support & Community

- **Issues**: [GitHub Issues](https://github.com/suchithnarayan/actions-guard-hub/issues)
- **Discussions**: [GitHub Discussions](https://github.com/suchithnarayan/actions-guard-hub/discussions)
- **Documentation**: This README and inline code documentation
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines

---

**Made with ❤️ for the GitHub Actions security community**

*Star ⭐ this repository if you find it useful!*
