# Contributing to RESK-LLM-TS

Thank you for your interest in contributing to RESK-LLM-TS! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security Considerations](#security-considerations)

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct. We expect all contributors to be respectful and professional.

## Getting Started

### Prerequisites

- Node.js (version 18.x or 20.x)
- npm or yarn
- Git
- TypeScript knowledge
- Understanding of LLM security concepts

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/resk-llm-js.git
   cd resk-llm-js
   ```

## Development Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Build the project:
   ```bash
   npm run build
   ```

3. Run tests:
   ```bash
   npm test
   ```

4. Run linting:
   ```bash
   npm run lint
   ```

## Making Changes

### Branch Naming Convention

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `security/description` - Security-related changes
- `test/description` - Test improvements

### Code Style

- Follow TypeScript best practices
- Use meaningful variable and function names
- Add comprehensive JSDoc comments for public APIs
- Maintain 80-character line limit where reasonable
- Use strict TypeScript configuration

### Security Guidelines

- **Never commit API keys or sensitive data**
- Add security-focused unit tests for new features
- Follow principle of least privilege
- Validate all inputs thoroughly
- Use parameterized patterns for security checks

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:all

# Run specific test suite
npm run test:frontend
```

### Writing Tests

- Write comprehensive unit tests for all new features
- Include security test cases
- Test both positive and negative scenarios
- Mock external dependencies properly
- Ensure tests clean up resources (timers, event listeners)

### Test Structure

```typescript
describe('Component Name', () => {
    let component: ComponentType;
    
    beforeEach(() => {
        // Setup
    });
    
    afterEach(() => {
        // Cleanup to prevent resource leaks
        component?.dispose();
    });
    
    test('Should handle expected behavior', () => {
        // Test implementation
    });
});
```

## Submitting Changes

### Pull Request Process

1. **Create a new branch** from `main`
2. **Make your changes** following the guidelines above
3. **Add tests** for your changes
4. **Update documentation** if needed
5. **Ensure all tests pass**:
   ```bash
   npm test
   npm run lint
   npm run build
   ```
6. **Commit with descriptive messages**:
   ```bash
   git commit -m "feat: add advanced prompt injection detection"
   ```
7. **Push to your fork** and create a pull request

### Commit Message Format

Use conventional commits:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Test changes
- `refactor:` - Code refactoring
- `security:` - Security improvements
- `perf:` - Performance improvements

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated if needed
- [ ] Security implications considered
- [ ] Breaking changes documented
- [ ] Performance impact assessed

## Security Considerations

### Reporting Security Issues

Please report security vulnerabilities through our [Security Policy](SECURITY.md). Do not create public issues for security vulnerabilities.

### Security Testing

- Include security-focused test cases
- Test with malicious inputs
- Verify proper input sanitization
- Check for information leakage
- Test error handling paths

### Code Security

- Avoid using `eval()` or similar dynamic code execution
- Sanitize all user inputs
- Use secure coding practices
- Follow OWASP guidelines
- Implement proper error handling

## Development Scripts

```bash
# Development
npm run build          # Build TypeScript
npm run lint           # Run ESLint
npm test              # Run tests
npm run test:all      # Run tests with coverage

# Examples
npm run example:basic           # Basic usage example
npm run example:express         # Express integration
npm run example:advanced        # Advanced security usage
npm run example:vector          # Vector database setup
npm run example:frontend-security  # Frontend security
npm run example:multi-provider   # Multi-provider usage
```

## Project Structure

```
src/
├── frontend/           # Frontend security components
├── security/          # Core security modules
├── providers/         # LLM provider interfaces
├── vector_stores/     # Vector database integration
├── types.ts          # TypeScript type definitions
└── index.ts          # Main entry point

test/                 # Test files
examples/             # Usage examples
docs/                 # Documentation
```

## Release Process

Releases are automated through GitHub Actions when version tags are pushed:

1. Update version in `package.json`
2. Create and push a version tag: `git tag v1.0.0 && git push origin v1.0.0`
3. GitHub Actions will run tests and publish to npm automatically

## Getting Help

- Check existing [issues](https://github.com/Resk-Security/resk-llm-js/issues)
- Read the [documentation](README.md)
- Join our community discussions

## Recognition

Contributors will be recognized in our changelog and contributors list. Thank you for helping make LLM interactions safer!