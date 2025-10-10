# Architecture Overview

This document provides a comprehensive overview of the GitHub Actions Security Scanner's architecture, design decisions, and component interactions.

## 🏗️ System Architecture

The scanner follows a **modular, layered architecture** designed for maintainability, extensibility, and testability.

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Interface Layer                      │
│                 actionsguardhub.py                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                 Application Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  Input Manager  │  │ Scanner Core    │  │ Report Gen   │ │
│  │ input_manager.py│  │scanner_core.py  │  │report_gen.py │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                   Service Layer                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────┐ │
│  │GitHub Client│ │  AI Core    │ │File Processor││ Auth   │ │
│  │github_client│ │  ai_core.py │ │file_proc.py │ │auth.py │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                 External APIs                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
│  │ GitHub API  │ │ Gemini API  │ │    File System          ││
│  └─────────────┘ └─────────────┘ └─────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 📁 File Structure Overview

```
actions-guard-hub/
├── 🎯 Core Application Files
│   ├── actionsguardhub.py     # Main CLI entry point
│   ├── scanner_core.py             # Orchestration & workflow management
│   ├── github_auth.py              # Authentication management
│   ├── input_manager.py            # Input processing & validation
│   └── report_generator.py         # Human-readable report generation
│
├── 🔧 Modular Service Components
│   ├── github_client.py            # GitHub API interactions
│   ├── ai_core.py                  # LangChain-based AI model management
│   └── file_processor.py           # File extraction & processing
│
├── ⚙️ Configuration Files
│   ├── ai_model_costs.json         # AI model cost configuration
│   ├── env.example                 # Environment variable template
│   ├── requirements.txt      # Python dependencies
│   └── prompt.txt                  # Security analysis prompt
│
├── 📚 Documentation
│   ├── README.md                   # User guide & setup instructions
│   ├── CONTRIBUTING.md             # Developer contribution guide
│   ├── ARCHITECTURE.md             # Technical architecture (this file)
│   └── CHANGELOG.md                # Version history & changes
│
├── 🌐 Web Dashboard
│   └── frontend/                   # Interactive web interface
│       ├── index.html              # Main dashboard
│       ├── css/style.css           # Styling
│       ├── js/                     # JavaScript functionality
│       ├── output/               # JSON scan results
│       └── output-metadata/        # Scan metadata
│
├── 📊 Output Directories
│   ├── scan-reports/               # Human-readable text reports
│   └── frontend/action-stats.json # Repository statistics
│
└── 🛠️ Utilities & Tools
    └── utils/                      # Helper scripts & utilities
```

## 🧩 Component Details

### 1. CLI Interface Layer

**File**: `actionsguardhub.py`

**Responsibilities**:
- Command-line argument parsing
- Application configuration
- High-level workflow orchestration
- Error handling and user feedback

**Key Classes**:
- `GHASecurityScanner`: Main application orchestrator

### 2. Application Layer

#### Scanner Core (`scanner_core.py`)
**Purpose**: Central orchestration of the scanning workflow

**Key Responsibilities**:
- Workflow management and coordination
- Component integration and dependency injection
- Metadata management and caching
- Result aggregation and processing

**Key Methods**:
```python
def scan_action(action_ref: str, skip_ai_scan: bool = False) -> Dict[str, Any]
def _perform_fresh_scan(action_ref: str, owner: str, repo: str, version: str) -> Dict[str, Any]
def _update_repository_metadata(owner_repo: str, force_update: bool = False)
```

#### Input Manager (`input_manager.py`)
**Purpose**: Process different types of input (actions, repositories, organizations)

**Key Responsibilities**:
- Input validation and parsing
- Multi-format input support
- Action discovery from repositories/organizations

#### Report Generator (`report_generator.py`)
**Purpose**: Generate human-readable reports from scan results

**Key Responsibilities**:
- Text report generation
- Batch report creation
- Result formatting and presentation

### 3. Service Layer

#### GitHub Client (`github_client.py`)
**Purpose**: Handle all GitHub API interactions

**Key Responsibilities**:
- Repository metadata collection
- Release and tag information retrieval
- Action source code downloading
- Rate limiting and authentication handling

**Key Features**:
- Automatic retry with exponential backoff
- Comprehensive error handling
- Efficient pagination for large datasets
- Smart caching to reduce API calls

**Interface**:
```python
class GitHubClient:
    def get_repository_stats(owner: str, repo: str) -> Optional[Dict]
    def download_action(owner: str, repo: str, version: str) -> Optional[str]
    def resolve_version_and_sha(owner: str, repo: str, version: str) -> Tuple[str, Optional[str]]
```

#### AI Core (`ai_core.py`)
**Purpose**: LangChain-based AI model management for security analysis

**Key Responsibilities**:
- Multi-provider AI support through LangChain framework
- Security analysis execution with unified interface
- JSON validation and repair
- Configurable cost calculation and token tracking
- Environment variable validation and setup guidance

**LangChain Architecture**:
```python
class AIModelInterface(ABC):
    @abstractmethod
    def analyze_security(prompt: str, action_files: Dict[str, str]) -> Dict[str, Any]
    
    @abstractmethod
    def validate_json(content: str) -> str
    
    @abstractmethod
    def calculate_cost(input_tokens: int, output_tokens: int, context_tokens: int) -> float

class LangChainGeminiModel(AIModelInterface):
    # Google Gemini via langchain-google-genai
    def __init__(self, model="gemini-2.5-pro", api_key=None, **kwargs):
        self.llm = ChatGoogleGenerativeAI(model=model, api_key=api_key, **kwargs)

class LangChainOpenAIModel(AIModelInterface):
    # OpenAI via langchain-openai
    def __init__(self, model="gpt-4o-mini", api_key=None, **kwargs):
        self.llm = ChatOpenAI(model=model, api_key=api_key, **kwargs)

class AICore:
    # Factory and management layer with LangChain integration
    def __init__(self, model_type="gemini", model_name=None, **config):
        self.model = self._create_model(model_type, model_name, **config)

class CostCalculator:
    # JSON-configurable cost calculation for all providers
    def calculate_cost(self, provider: str, model: str, input_tokens: int, output_tokens: int)
```

**Key Features**:
- **LangChain Integration**: Unified interface for multiple AI providers
- **Cost Configuration**: JSON-based cost calculation (`ai_model_costs.json`)
- **Environment Validation**: Automatic API key validation and helpful error messages
- **Extensibility**: Easy to add new providers by implementing LangChain model classes

#### File Processor (`file_processor.py`)
**Purpose**: Handle file extraction, filtering, and processing

**Key Responsibilities**:
- Action file extraction from downloaded archives
- Intelligent file filtering (exclude binaries, dependencies, etc.)
- Content validation and preparation for AI analysis
- Security pattern detection

**Key Features**:
- Configurable file filtering rules
- Binary file detection
- Size limits and safety checks
- Content preprocessing for AI analysis

#### Authentication Manager (`github_auth.py`)
**Purpose**: Handle GitHub authentication methods

**Key Responsibilities**:
- Multiple authentication method support
- Token management and refresh
- Rate limit information

## 🔄 Data Flow

### 1. Scan Initiation
```
User Input → CLI Parser → Input Manager → Action List
```

### 2. Action Processing
```
Action Reference → GitHub Client → Repository Metadata
                ↓
Action Reference → GitHub Client → Source Code Download
                ↓
Downloaded Files → File Processor → Filtered & Processed Files
                ↓
Processed Files → AI Core → Security Analysis
                ↓
Analysis Results → Scanner Core → Metadata Update
```

### 3. Report Generation
```
Scan Results → Report Generator → Human-Readable Reports
            ↓
            → Web Dashboard → JSON Files
```

## 🎯 Design Principles

### 1. Single Responsibility Principle
Each module has one clear, focused responsibility:
- `github_client.py`: GitHub API operations only
- `ai_core.py`: LangChain-based AI model management with multi-provider support
- `file_processor.py`: File processing only

### 2. Dependency Injection
Components are injected rather than hard-coded:
```python
class GitHubActionsScanner:
    def __init__(self, config: Dict, auth_manager: GitHubAuthManager):
        self.github_client = GitHubClient(auth_manager)
        self.ai_core = create_ai_core("gemini")
        self.file_processor = create_file_processor()
```

### 3. Interface Segregation
Clean interfaces for extensibility:
- `AIModelInterface` for adding new AI models
- Factory functions for component creation
- Abstract base classes where appropriate

### 4. Open/Closed Principle
Open for extension, closed for modification:
- New AI models can be added without changing existing code
- New file processing rules can be added through configuration
- New authentication methods can be plugged in

### 5. Error Handling Strategy
Comprehensive error handling at each layer:
- **Service Layer**: Handle external API errors gracefully
- **Application Layer**: Aggregate and contextualize errors
- **CLI Layer**: Present user-friendly error messages

## 🔌 Extension Points

### Adding New AI Models

1. **Implement Interface**:
   ```python
   class NewAIModel(AIModelInterface):
       def analyze_security(self, prompt, files):
           # Implementation
   ```

2. **Register in Factory**:
   ```python
   def _create_model(self, model_type, **config):
       if model_type == "new_model":
           return NewAIModel(**config)
   ```

### Adding New Authentication Methods

1. **Extend AuthType Enum**:
   ```python
   class AuthType(Enum):
       NEW_AUTH = "new_auth"
   ```

2. **Implement in GitHubAuthManager**:
   ```python
   def _initialize_new_auth(self):
       # Implementation
   ```

### Adding New File Processing Rules

1. **Extend FileProcessor**:
   ```python
   class CustomFileProcessor(FileProcessor):
       def __init__(self):
           super().__init__()
           self.custom_rules = {...}
   ```

2. **Use Factory Function**:
   ```python
   def create_file_processor(processor_type="default"):
       if processor_type == "custom":
           return CustomFileProcessor()
   ```

## 📊 Performance Considerations

### 1. Caching Strategy
- **Metadata Caching**: Repository metadata cached for 6 hours
- **Scan Result Caching**: Existing scans reused when possible
- **API Response Caching**: GitHub API responses cached appropriately

### 2. Rate Limiting
- **Exponential Backoff**: Automatic retry with increasing delays
- **Request Queuing**: Batch requests to stay within limits
- **Smart Scheduling**: Prioritize important requests

### 3. Memory Management
- **Streaming Processing**: Large files processed in chunks
- **Temporary File Cleanup**: Automatic cleanup of downloaded files
- **Lazy Loading**: Components loaded only when needed

### 4. Concurrency
- **Async-Ready Design**: Components designed for future async support
- **Thread Safety**: Shared resources properly protected
- **Parallel Processing**: Batch operations can be parallelized

## 🔒 Security Considerations

### 1. Credential Management
- **Environment Variables**: Sensitive data in environment variables
- **No Logging**: Credentials never logged or printed
- **Secure Storage**: Temporary files in secure locations

### 2. Input Validation
- **Action Reference Validation**: Proper parsing and validation
- **File Size Limits**: Prevent processing of extremely large files
- **Content Filtering**: Skip potentially dangerous file types

### 3. API Security
- **HTTPS Only**: All API calls use HTTPS
- **Token Refresh**: Automatic token refresh for GitHub Apps
- **Rate Limit Respect**: Never exceed API rate limits

## 🧪 Testing Strategy

### 1. Unit Tests
- **Component Isolation**: Each component tested independently
- **Mock External Dependencies**: GitHub API, AI APIs mocked
- **Edge Case Coverage**: Error conditions and edge cases tested

### 2. Integration Tests
- **Component Interaction**: Test component integration
- **End-to-End Workflows**: Full scan workflows tested
- **Real API Testing**: Optional tests with real APIs

### 3. Performance Tests
- **Load Testing**: Test with large repositories
- **Memory Usage**: Monitor memory consumption
- **Rate Limit Handling**: Test rate limit scenarios

## 🚀 Future Enhancements

### 1. Planned Features
- **Multiple AI Model Support**: OpenAI, Claude, local models
- **Enhanced Security Checks**: More vulnerability patterns
- **Performance Improvements**: Parallel processing, better caching
- **GitHub Integration**: GitHub Apps, Actions integration

### 2. Architecture Evolution
- **Microservices**: Potential split into microservices
- **Event-Driven**: Event-driven architecture for scalability
- **Plugin System**: Full plugin architecture for extensions
- **Cloud Deployment**: Cloud-native deployment options

## 📚 References

- **Design Patterns**: [Gang of Four Design Patterns](https://en.wikipedia.org/wiki/Design_Patterns)
- **Clean Architecture**: [Robert C. Martin's Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- **Python Best Practices**: [The Hitchhiker's Guide to Python](https://docs.python-guide.org/)
- **API Design**: [REST API Design Best Practices](https://restfulapi.net/)

---

This architecture is designed to be **maintainable**, **extensible**, and **testable**. Each component has clear responsibilities and well-defined interfaces, making it easy for developers to understand, modify, and extend the system.

For questions about the architecture or suggestions for improvements, please open an issue or discussion on GitHub.
