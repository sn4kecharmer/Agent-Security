# Contributing to Agent Security Scanner

Thank you for your interest in contributing to the Agent Security Scanner! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Issues

- Use the GitHub issue tracker to report bugs or suggest features
- Include detailed steps to reproduce the issue
- For security vulnerabilities, please see our [Security Policy](SECURITY.md)
- Include relevant logs, error messages, and system information
- Specify the version of the scanner you're using

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature/fix
3. Make your changes
4. Add tests for new functionality
5. Update documentation as needed
6. Ensure all tests pass
7. Submit a pull request

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/agent-security-scanner.git
   cd agent-security-scanner
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .  # Install package in editable mode
   ```

4. Run tests:
   ```bash
   python -m pytest
   ```

### Code Style

- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions focused and single-purpose
- Write meaningful commit messages

### Testing

- Write unit tests for new functionality
- Ensure existing tests pass
- Include integration tests for complex features
- Test edge cases and error conditions
- Maintain test coverage

### Documentation

- Update README.md for major changes
- Document new features and configuration options
- Include examples for new functionality
- Update docstrings for modified functions
- Keep the documentation clear and concise

### Security Considerations

- Follow security best practices
- Validate all inputs
- Handle sensitive data appropriately
- Include security tests for new features
- Document security implications of changes

## Project Structure

```
agent-security-scanner/
├── agent_security/          # Main package directory
│   ├── cli.py              # Command-line interface
│   ├── scanner.py          # Core scanning functionality
│   ├── patterns.py         # Security patterns and rules
│   └── models.py           # Data models
├── examples/               # Example configurations
├── tests/                  # Test suite
├── docs/                   # Documentation
└── scripts/               # Utility scripts
```

## Release Process

1. Update version in `setup.py`
2. Update CHANGELOG.md
3. Create a release tag
4. Build and test the package
5. Deploy to PyPI

## Questions?

Feel free to open an issue for any questions about contributing to the project.

Thank you for contributing to making LLM agents more secure! 