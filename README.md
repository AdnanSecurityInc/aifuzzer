# AI-Powered Adaptive API Fuzzer

**The World's First Production AI-Based Adaptive API Fuzzer**

Author: Adnan Ahmad - Adnan Security Inc.

## Overview

This tool represents a breakthrough in API security testing by utilizing large language models (LLMs) to dynamically generate and refine payloads based on real-time API feedback. Unlike traditional fuzzers that rely on static wordlists or random mutations, this fuzzer learns from each API response and intelligently adapts its testing strategy.

## Key Features

- **🧠 AI-Powered Payload Generation**: Uses Claude 3.7 Sonnet (via OpenRouter) to analyze API responses and generate intelligent payloads
- **🔄 Adaptive Learning**: Learns from each API response and adjusts the fuzzing strategy in real-time
- **🌐 Universal Compatibility**: Works with any REST API endpoint
- **🔐 Custom Authentication**: Supports custom headers for API keys, bearer tokens, and other auth methods
- **📊 Intelligent Context Extraction**: Automatically analyzes URL structure to provide context to the AI
- **🔍 Burp Suite Integration**: Proxy requests through Burp for detailed inspection
- **💾 Automatic Result Saving**: Saves interesting responses (2xx, 5xx, permission-related) to JSON
- **📝 Custom Context Injection**: Provide API-specific context to improve AI understanding
- **🎯 Multi-Method Support**: Test with GET, POST, PUT, DELETE, PATCH

## How It Works

1. **Initial Request**: Starts with an empty payload `{}` to trigger informative error messages
2. **AI Analysis**: The AI analyzes the API response (errors, missing fields, validation messages)
3. **Payload Generation**: Based on the analysis, generates an improved payload
4. **Iteration**: Repeats the process, learning from each response
5. **Result Capture**: Saves all interesting responses for later analysis

## Academic Significance

This fuzzer demonstrates a novel approach to API security testing:

- **Feedback Loop Learning**: Unlike static fuzzers, it creates a continuous feedback loop with the target API
- **Semantic Understanding**: The LLM can understand error messages and API documentation in context
- **Dynamic Strategy Adaptation**: Changes testing approach based on what it learns
- **Reduced False Positives**: Intelligent payload generation reduces noise compared to brute-force methods

## Installation

```bash
# Clone or download the fuzzer
git clone <your-repo-url>
cd aifuzzer

# Install dependencies
pip install requests urllib3

# Set your OpenRouter API key
export OPENROUTER_API_KEY="your-api-key-here"
```

## Usage

### Basic Fuzzing

```bash
# Fuzz a simple endpoint
python3 aifuzzer.py https://api.example.com/v1/users/123/profile

# Specify number of iterations
python3 aifuzzer.py https://api.example.com/v1/users -i 20
```

### With Authentication

```bash
# Bearer token
python3 aifuzzer.py https://api.example.com/v1/data \
  -H "Authorization: Bearer YOUR_TOKEN"

# API Key
python3 aifuzzer.py https://api.example.com/v1/data \
  -H "X-API-Key: your-api-key"

# Multiple headers
python3 aifuzzer.py https://api.example.com/v1/data \
  -H "X-API-Key: key123" \
  -H "X-Session-ID: sess456"
```

### With Custom Context

Providing context helps the AI understand the API better:

```bash
# Inline context
python3 aifuzzer.py https://api.example.com/v1/orders \
  -c "This endpoint requires orderId (string), amount (number), and paymentMethod (string: card/paypal/crypto)"

# Context from file
python3 aifuzzer.py https://api.example.com/v1/payment \
  --context-file api_context.txt
```

### Different HTTP Methods

```bash
# Test with POST (default)
python3 aifuzzer.py https://api.example.com/v1/resource

# Test with multiple methods
python3 aifuzzer.py https://api.example.com/v1/resource -m POST PUT DELETE

# Test with GET
python3 aifuzzer.py https://api.example.com/v1/resource -m GET
```

### With Burp Suite

```bash
# Default Burp port (8080)
python3 aifuzzer.py https://api.example.com/v1/data -b

# Custom Burp port
python3 aifuzzer.py https://api.example.com/v1/data -b --burp-port 9090
```

### Single Test Mode

Just test the endpoint without AI fuzzing:

```bash
python3 aifuzzer.py https://api.example.com/v1/status -s
```

### Custom Initial Payload

```bash
python3 aifuzzer.py https://api.example.com/v1/users \
  -p '{"name": "test", "email": "test@example.com"}'
```

## Output

The fuzzer provides detailed output for each iteration:

```
🔄 FUZZING ITERATION 1/10
==================================================
📡 POST request with payload:
{}

📥 Response (400 Bad Request) in 0.23s:
{
  "error": "Missing required field: userId"
}

🧠 Generating next payload...
💡 AI Reasoning: The API indicates a required field 'userId' is missing. I'll add this field with a test value.
📝 Next payload generated:
{
  "userId": "test-user-123"
}
```

Interesting results are automatically saved to `api_fuzzing_results_<timestamp>.json`.

## Configuration

### Environment Variables

- `OPENROUTER_API_KEY` (required): Your OpenRouter API key for AI functionality

### Command Line Options

```
positional arguments:
  url                   Full URL to test (e.g., https://api.example.com/v1/users/123)

optional arguments:
  -h, --help            show this help message and exit
  -i ITERATIONS, --iterations ITERATIONS
                        Number of fuzzing iterations (default: 10)
  -m METHODS [METHODS ...], --methods METHODS [METHODS ...]
                        HTTP methods to use (default: POST)
  -b, --burp            Use Burp proxy for request inspection
  --burp-port BURP_PORT
                        Burp proxy port (default: 8080)
  -H HEADERS, --header HEADERS
                        Custom header in format 'Name: Value' (can be used multiple times)
  -p PAYLOAD, --payload PAYLOAD
                        Initial JSON payload (optional, default: empty {})
  -s, --single          Single test only, no fuzzing
  -v, --verbose         Verbose output
  -c CONTEXT, --context CONTEXT
                        Custom context to inject into AI system prompt
  --context-file CONTEXT_FILE
                        File containing custom context
  --base-url BASE_URL   Base URL if you want to provide relative paths
```

## Advanced Usage

### Context File Example

Create a file `api_context.txt`:

```
API Authentication: Requires Bearer token in Authorization header
Common Parameters:
  - userId: string, format UUID
  - timestamp: integer, Unix timestamp
  - signature: string, HMAC-SHA256 of request body
Error Format: JSON with 'code', 'message', and 'details' fields
Rate Limiting: 100 requests per minute
```

Then use it:

```bash
python3 aifuzzer.py https://api.example.com/v1/users \
  --context-file api_context.txt \
  -H "Authorization: Bearer token123"
```

### Batch Testing

Test multiple endpoints:

```bash
#!/bin/bash
endpoints=(
  "https://api.example.com/v1/users"
  "https://api.example.com/v1/orders"
  "https://api.example.com/v1/products"
)

for endpoint in "${endpoints[@]}"; do
  echo "Testing: $endpoint"
  python3 aifuzzer.py "$endpoint" -i 5 -H "Authorization: Bearer $TOKEN"
done
```

## Security & Ethics

**IMPORTANT**: This tool is for authorized security testing only. 

- ✅ Use only on APIs you own or have explicit permission to test
- ✅ Respect rate limits and API terms of service
- ✅ Use responsibly in bug bounty programs (check scope)
- ❌ Do not use for unauthorized testing
- ❌ Do not use to cause harm or disruption

## Troubleshooting

### "OPENROUTER_API_KEY not set"

Set the environment variable:
```bash
export OPENROUTER_API_KEY="your-key-here"
```

### Burp Proxy Connection Failed

Ensure Burp is running and listening on the correct port (default: 8080).

### Invalid URL Error

Make sure your URL includes the scheme:
- ✅ `https://api.example.com/v1/users`
- ❌ `api.example.com/v1/users`

### High Token Usage

Each fuzzing iteration uses AI tokens. For cost control:
- Use fewer iterations (`-i 5`)
- Use context files to improve efficiency
- Test critical endpoints first

## Contributing

Contributions are welcome! This is a research project and there's much room for improvement:

- Additional AI models (GPT-4, Gemini, etc.)
- GraphQL support
- SOAP/XML support
- Automated authentication workflows
- Better result analysis and reporting

## Academic Citation

If you use this tool in research or want to reference it:

```
Ahmad, Adnan. Adnan Security Inc. (2024-2025). AI-Powered Adaptive API Fuzzer: 
The World's First Production AI-Based Adaptive API Security Testing Tool. 
Retrieved from [URL]
```

## License

MIT License - See LICENSE file for details.

This tool is provided for security research and authorized testing only.

## Author

**Adnan Ahmad**
- Company: Adnan Security Inc.
- Email: adnan@adnansecurity.com
- Research: API Security & AI-Assisted Security Testing

## Acknowledgments

- OpenRouter for providing API access to Claude
- The API security testing community
- Bug bounty platforms for providing real-world testing opportunities

---

**Remember**: Always test responsibly and ethically. Happy fuzzing! 🚀
