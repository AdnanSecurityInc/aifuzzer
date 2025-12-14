# Contributing to AI-Powered Adaptive API Fuzzer

Thank you for your interest in contributing to this project!

## How to Contribute

### Reporting Issues
- Use the GitHub issue tracker
- Provide clear description of the problem
- Include steps to reproduce
- Share relevant logs (remove sensitive data)

### Suggesting Enhancements
- Open an issue with the "enhancement" label
- Describe the feature and use case
- Explain how it improves the tool

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
   - Follow existing code style
   - Add comments for complex logic
   - Test your changes
4. **Commit with clear messages**
   ```bash
   git commit -m "Add feature: description"
   ```
5. **Push and create pull request**

### Code Guidelines

- **Python Style**: Follow PEP 8
- **Documentation**: Update README for new features
- **Testing**: Ensure code runs without errors
- **Security**: Never commit API keys or sensitive data

### Areas for Contribution

- Additional AI model support (GPT-4, Gemini, etc.)
- GraphQL/gRPC protocol support
- Improved error handling
- Performance optimizations
- Better result analysis
- Additional authentication methods
- Documentation improvements

### Testing Your Changes

```bash
# Test basic functionality
python3 aifuzzer.py https://jsonplaceholder.typicode.com/posts -i 3

# Test with custom headers
python3 aifuzzer.py https://jsonplaceholder.typicode.com/posts \
  -H "X-Test: value" -i 2

# Verify no errors
python3 -m py_compile aifuzzer.py
```

### Questions?

Figure it out. No support is provided and the code is posted as-is.

## Code of Conduct

- Be respectful and constructive
- Focus on improving the tool
- Help others learn and grow
- Use the tool ethically and legally

Thank you for contributing!
