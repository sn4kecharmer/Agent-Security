# Agent Security Comprehensive Test Plan

This test plan outlines the testing strategy for the Agent Security scanner. It should be run every time updates are made to ensure existing features continue to work correctly.

## 1. Test Types

### 1.1 Unit Tests
- Focused on testing individual components/functions
- Isolated from external dependencies
- Fast execution

### 1.2 Integration Tests
- Test interactions between components
- May involve file system operations
- Verify end-to-end flows

### 1.3 Edge Case Tests
- Tests for unusual or boundary conditions
- Malformed inputs
- Complex nested configurations

## 2. Test Components

### 2.1 Core Scanner Components
- `scanner.py`: Main scanning functionality
- `file_scanner.py`: File parsing and scanning
- `git_scanner.py`: Git repository scanning
- `patterns.py`: Security pattern detection

### 2.2 CLI Interface
- Command-line argument parsing
- Output formatting (table, JSON, CSV)
- File path handling

### 2.3 Models
- Data structures and transformations
- Risk level calculations
- Report generation

## 3. Test Automation

### 3.1 CI/CD Integration
```yaml
# .github/workflows/test.yml
name: Run Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install pytest pytest-cov
          pip install -e .
      - name: Run tests
        run: |
          pytest tests/ --cov=agent_security -v
```

### 3.2 Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest-check
        name: pytest-check
        entry: pytest tests/ -v
        language: system
        pass_filenames: false
        always_run: true
```

## 4. Test Cases

### 4.1 Scanner Tests
- Test Python file scanning
- Test YAML configuration scanning
- Test Git repository scanning
- Test handling of ignored findings
- Test detection of all security patterns

### 4.2 CLI Tests
- Test argument parsing
- Test output formatting (table, JSON, CSV)
- Test handling of different file types
- Test export to different formats

### 4.3 Pattern Detection Tests
- Test each pattern category (LLM, tools, execution)
- Test nested pattern detection
- Test complex configurations
- Test mitigation recognition

### 4.4 Risk Calculation Tests
- Test overall risk calculation from multiple findings
- Test risk level comparisons
- Test risk reporting

## 5. Test Plan Execution

### 5.1 Regular Testing
Run the full test suite during:
- Pre-commit (fast tests)
- Pre-push (all tests)
- CI/CD pipeline (all tests + coverage)

### 5.2 Test Command
```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=agent_security

# Run specific test categories
pytest tests/test_scanner.py
pytest tests/test_cli.py
pytest tests/edge_cases.py
pytest tests/test_crewai_and_ignore.py
```

## 6. Regression Testing

### 6.1 Test Additions for New Features
When adding new features:
- Create specific tests for the new functionality
- Add edge cases for the new feature
- Update existing tests if the feature changes behavior

### 6.2 Bug Fix Verification
For each bug fix:
- Create a test that reproduces the bug
- Verify the test fails before the fix
- Verify the test passes after the fix

## 7. Test Data Management

### 7.1 Fixtures
- Create reusable test fixtures for common test data
- Maintain sample files of various types (Python, YAML)
- Create fixtures for different security patterns

### 7.2 Sample Files
Maintain a collection of sample files in `tests/fixtures/`:
- Safe configurations
- Configurations with known vulnerabilities
- Edge cases and complex structures

## 8. New Test Types to Implement

### 8.1 Performance Tests
- Test scanner performance on large codebases
- Measure execution time for different file types/sizes
- Establish performance baselines

### 8.2 Compatibility Tests
- Test with different Python versions (3.8, 3.9, 3.10, 3.11)
- Test with different operating systems
- Test with different Git providers

## 9. Continuous Improvement

### 9.1 Coverage Targets
- Maintain >90% code coverage
- Focus on covering critical security patterns
- Ensure edge cases are well-covered

### 9.2 Test Review
- Review tests during code reviews
- Update tests when patterns are modified
- Remove obsolete tests

## 10. Testing Tools

### 10.1 Required Tools
- pytest: Main testing framework
- pytest-cov: Code coverage
- pytest-mock: Mocking
- pytest-benchmark (future): Performance testing

### 10.2 Helper Scripts
Create helper scripts in `tests/utils/`:
- Test file generators
- Test data builders
- Result comparators

## 11. Implementation Plan

### 11.1 Priority Order
1. Core scanner tests (maintain existing)
2. CLI interface tests (maintain existing)
3. Add performance tests
4. Add compatibility tests
5. Improve coverage in weaker areas

### 11.2 Timeline
- Phase 1: Ensure all existing tests pass (immediate)
- Phase 2: Add missing tests for current features (short-term)
- Phase 3: Implement performance testing (medium-term)
- Phase 4: Implement compatibility testing (long-term) 