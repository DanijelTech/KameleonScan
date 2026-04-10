# Contributing to KameleonScan

Thank you for your interest in contributing to KameleonScan!

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details

### Suggesting Features

1. Check existing feature requests
2. Describe the problem you're trying to solve
3. Explain the proposed solution
4. Consider alternatives

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Follow our code style
4. Write tests for new functionality
5. Ensure all tests pass
6. Update documentation if needed
7. Submit a pull request

## Development Setup

```bash
# Clone the repo
git clone https://github.com/DanijelTech/KameleonScan.git
cd KameleonScan

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -r KameleonScan/tests/requirements.txt
pip install black flake8 isort mypy pylint pytest

# Run tests
pytest KameleonScan/ -v
```

## Code Style

- We use **Black** for code formatting (line length: 100)
- We use **isort** for import sorting
- We use **flake8** for linting
- We use **mypy** for type checking

Run formatters before committing:
```bash
black KameleonScan/
isort KameleonScan/
flake8 KameleonScan/
```

## Testing

- Write tests for all new functionality
- Run tests: `pytest KameleonScan/ -v`
- Run with coverage: `pytest --cov=KameleonScan`
- Mark slow tests: `@pytest.mark.slow`

## Commit Messages

- Use clear, descriptive commit messages
- Reference issues in commits: "Fixes #123"
- Use imperative mood: "Add feature" not "Added feature"

## Recognition

Contributors will be recognized in:
- README.md contributors section
- CHANGELOG.md
- Release notes

## Questions?

- Open an issue for bugs/features
- Join our community forum
- Email: info@KameleonScan.org