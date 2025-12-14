#!/bin/bash
# AI-Powered API Fuzzer - Usage Examples
# These examples demonstrate different ways to use the fuzzer

# Make sure OPENROUTER_API_KEY is set
if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "Error: OPENROUTER_API_KEY environment variable not set"
    echo "Set it with: export OPENROUTER_API_KEY='your-key-here'"
    exit 1
fi

echo "🚀 AI-Powered API Fuzzer - Example Usage"
echo "=========================================="
echo ""

# Example 1: Basic fuzzing
echo "📌 Example 1: Basic API fuzzing"
echo "python3 aifuzzer.py https://jsonplaceholder.typicode.com/posts/1 -i 3"
echo ""

# Example 2: With custom headers
echo "📌 Example 2: With authentication header"
echo "python3 aifuzzer.py https://api.example.com/v1/users \\"
echo "  -H 'Authorization: Bearer YOUR_TOKEN' \\"
echo "  -i 5"
echo ""

# Example 3: Multiple methods
echo "📌 Example 3: Test multiple HTTP methods"
echo "python3 aifuzzer.py https://api.example.com/v1/resource \\"
echo "  -m GET POST PUT DELETE \\"
echo "  -i 3"
echo ""

# Example 4: With custom context
echo "📌 Example 4: With custom context for better AI understanding"
echo "python3 aifuzzer.py https://api.example.com/v1/orders \\"
echo "  -c 'This endpoint requires orderId (UUID), amount (decimal), status (pending|completed|cancelled)' \\"
echo "  -i 10"
echo ""

# Example 5: Using context file
echo "📌 Example 5: Using context from file"
echo "python3 aifuzzer.py https://api.example.com/v1/payment \\"
echo "  --context-file example_context.txt \\"
echo "  -H 'Authorization: Bearer TOKEN' \\"
echo "  -i 8"
echo ""

# Example 6: With Burp Suite
echo "📌 Example 6: Proxy through Burp Suite for inspection"
echo "python3 aifuzzer.py https://api.example.com/v1/data \\"
echo "  -b --burp-port 8080 \\"
echo "  -H 'X-API-Key: your-key'"
echo ""

# Example 7: Single test (no fuzzing)
echo "📌 Example 7: Single test mode"
echo "python3 aifuzzer.py https://api.example.com/v1/status -s"
echo ""

# Example 8: With initial payload
echo "📌 Example 8: Start with specific payload"
echo "python3 aifuzzer.py https://api.example.com/v1/users \\"
echo "  -p '{\"name\": \"test\", \"email\": \"test@example.com\"}' \\"
echo "  -i 5"
echo ""

# Example 9: Test public API (safe)
echo "📌 Example 9: Test a public API (JSONPlaceholder)"
echo "This is safe to run as a demo:"
echo ""
echo "python3 aifuzzer.py https://jsonplaceholder.typicode.com/posts -i 5 -m POST"
echo ""

# Example 10: Batch testing
echo "📌 Example 10: Batch test multiple endpoints"
echo "#!/bin/bash"
echo "ENDPOINTS=("
echo "  'https://api.example.com/v1/users'"
echo "  'https://api.example.com/v1/orders'"
echo "  'https://api.example.com/v1/products'"
echo ")"
echo ""
echo "for endpoint in \"\${ENDPOINTS[@]}\"; do"
echo "  echo \"Testing: \$endpoint\""
echo "  python3 aifuzzer.py \"\$endpoint\" -i 3 -H \"Authorization: Bearer \$TOKEN\""
echo "  sleep 5  # Rate limiting"
echo "done"
echo ""

echo "=========================================="
echo "💡 Tips:"
echo "  - Start with fewer iterations (-i 3) to test"
echo "  - Use context files for complex APIs"
echo "  - Enable Burp (-b) to inspect all requests"
echo "  - Results are saved to api_fuzzing_results_*.json"
echo "  - Use -s flag for quick endpoint testing"
echo ""
echo "⚠️  Remember: Only test APIs you're authorized to test!"
