# AI Repo Review

A static analysis tool for Python repositories. Detects security issues, code quality problems, and deprecated patterns.

## What It Does

| Category | Detects |
|----------|---------|
| **Security** | Hardcoded secrets, API keys, .env files, eval/exec usage, pickle vulnerabilities |
| **Code Quality** | Bare except clauses, deprecated datetime.utcnow(), missing type hints |
| **Dependencies** | Outdated packages, known CVEs (planned) |

## What It Does NOT Do

- **No code execution** — static analysis only
- **No external calls** — all analysis runs locally
- **No data retention** — results are ephemeral
- **No auto-fixes** — reports findings for human review

## Case Study: ChatterFix

Used this tool to audit a production CMMS application:

| Metric | Before | After | Result |
|--------|--------|-------|--------|
| Total findings | 27 | 11 | **-59%** |
| Critical | 0 | 0 | — |
| High | 12 | 7 | -5 |
| Low | 13 | 2 | -11 |

**16 real issues fixed** including:
- Bare `except:` clauses → specific exception types
- `datetime.utcnow()` → `datetime.now(timezone.utc)`
- Hardcoded bearer tokens → environment variables

**11 findings remain** — all documented as:
- False positives (string patterns in code analyzers)
- Intentional design (eval/exec in code reviewer tool)
- Safe by design (public Firebase API keys)

## Installation

```bash
git clone https://github.com/TheGringo-ai/ai-repo-review.git
cd ai-repo-review
pip install -r requirements.txt
```

## Usage

### Python API

```python
from review import detect_stack, run_all_analyzers

repo_path = "/path/to/repository"
stack_info = detect_stack(repo_path)
results = run_all_analyzers(repo_path, stack_info)

for category, findings in results.items():
    print(f"{category}: {len(findings)} findings")
```

### Web Interface

```bash
uvicorn app.main:app --port 8001
# Open http://localhost:8001
```

## Understanding Results

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **Critical** | Exploitable vulnerability | Fix immediately |
| **High** | Security risk or major issue | Fix before deploy |
| **Medium** | Code smell or potential problem | Review and decide |
| **Low** | Style issue or deprecation | Fix when convenient |

### Common False Positives

| Finding | Why It's OK |
|---------|-------------|
| `.env` files | Local dev files in .gitignore |
| Firebase API key in JS | Public by design (Firebase web config) |
| `eval()` in code analyzer | Required for code analysis tools |
| `pickle.load` | Performance caching with trusted data |
| `except:` in string patterns | Detection rules, not actual code |

## Project Structure

```
ai-repo-review/
├── app/
│   ├── main.py           # FastAPI app
│   ├── routers/review.py # Web endpoints
│   └── templates/        # HTML interface
├── review/
│   ├── cloner.py         # Git clone handling
│   ├── detector.py       # Language/stack detection
│   ├── analyzers.py      # Security & quality checks
│   └── reporter.py       # Report generation
└── requirements.txt
```

## License

MIT

## Contributing

Issues and PRs welcome. Please open an issue before submitting large changes.
