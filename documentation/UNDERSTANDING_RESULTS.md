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