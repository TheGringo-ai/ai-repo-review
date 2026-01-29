# AI Repo Review Tool

A static analysis tool that uses AI to review code repositories and generate reports on code quality, potential issues, and improvement suggestions.

## What This Does

- **Repository Analysis**: Scans source code files in a repository to identify patterns, structures, and potential problems.
- **Issue Identification**: Detects common code smells, potential bugs, security concerns, and maintainability issues.
- **Report Generation**: Produces structured reports summarizing findings with severity levels and file locations.
- **Multi-Language Support**: Analyzes repositories containing code in multiple programming languages.

## What This Does NOT Do

- **No Code Execution**: This tool performs static analysis only. It does not run, compile, or execute any code from the analyzed repository.
- **No Automated Pull Requests**: The tool generates reports but does not create, modify, or submit pull requests or commits.
- **No Authentication Storage**: The tool does not store credentials, tokens, or authentication information between sessions.
- **No Data Retention**: Analysis results are not retained after the session ends. Each analysis is independent and ephemeral.
- **No External Network Calls**: The tool does not send repository data to external services beyond the configured AI provider.

## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager

### Steps

```bash
# Clone the repository
git clone https://github.com/your-org/ai-repo-review.git
cd ai-repo-review

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your AI provider API key
```

## Usage

### Command Line Interface

```bash
# Analyze a local repository
python -m ai_repo_review /path/to/repository

# Analyze with specific output format
python -m ai_repo_review /path/to/repository --format json

# Analyze specific file types only
python -m ai_repo_review /path/to/repository --include "*.py,*.js"

# Save report to file
python -m ai_repo_review /path/to/repository --output report.md
```

### Web Interface

```bash
# Start the web server
python -m ai_repo_review --web

# Access the interface at http://localhost:8000
```

The web interface allows you to:
- Upload or specify a repository path
- Configure analysis options
- View reports in a formatted display
- Export reports in various formats

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--format` | Output format (text, json, markdown) | text |
| `--include` | File patterns to include | all supported |
| `--exclude` | File patterns to exclude | none |
| `--output` | Output file path | stdout |
| `--severity` | Minimum severity to report (low, medium, high) | low |
| `--web` | Start web interface | false |
| `--port` | Web server port | 8000 |

## Ethics and Responsible Use

This tool is intended for legitimate code review and quality assurance purposes. Users are expected to:

- **Obtain Authorization**: Only analyze repositories you own or have explicit permission to review.
- **Respect Privacy**: Do not use this tool to analyze private repositories without proper authorization.
- **Review AI Output**: AI-generated findings should be reviewed by qualified developers before taking action. The tool may produce false positives or miss actual issues.
- **No Malicious Use**: Do not use this tool to identify vulnerabilities in systems you do not have permission to test.
- **Comply with Terms of Service**: Ensure your use complies with the terms of service of the AI provider and any code hosting platforms involved.

The maintainers of this tool are not responsible for misuse or any damages resulting from the use of this software.

## License

MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.
