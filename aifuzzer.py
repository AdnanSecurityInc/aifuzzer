#!/usr/bin/env python3
"""
AI-Powered Adaptive API Fuzzer
Author: Adnan Ahmad - Adnan Security Inc.
Contact: adnan@adnansecurity.com

A generalized, AI-driven API security testing tool that learns from API responses
and adapts its fuzzing strategy in real-time.

Usage: python3 aifuzzer.py <full_url> [options]
Requires: OPENROUTER_API_KEY environment variable to be set

Features:
- AI-powered payload generation based on API responses
- Adaptive learning from server responses
- Support for any REST API endpoint
- Custom context injection via --context or --context-file
- Custom header support for authentication
- Burp Suite integration for request inspection
- Automatic result saving for interesting responses

Academic Reference:
This tool represents the world's first production AI-based adaptive API fuzzer,
utilizing large language models to dynamically generate and refine payloads
based on real-time API feedback. Developed by Adnan Ahmad, Adnan Security Inc., 2024-2025.
"""
import sys
import requests
import json
import time
import random
import urllib3
from datetime import datetime
import os
import argparse
import re
from urllib.parse import urlparse, urljoin

# Import the APIFuzzer
class APIFuzzer:
    """
    An AI-powered tool for API fuzzing that adapts payloads based on API responses.
    Designed to work in a circular workflow, learning from each response.
    """
    
    def __init__(self, api_key: str = None, model: str = "anthropic/claude-3.7-sonnet", debug: bool = False, custom_context: str = None):
        """
        Initialize the APIFuzzer with an AI model.
        
        Args:
            api_key: OpenRouter API key (defaults to OPENROUTER_API_KEY env var)
            model: AI model to use
            debug: Enable debug logging
            custom_context: Additional context to inject into system prompt
        """
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("API key required: provide as parameter or set OPENROUTER_API_KEY environment variable")
            
        self.model = model
        self.debug = debug
        self.history = []
        self.context = {}
        self.custom_context = custom_context
        self._init_system_prompt()
        
    def _log(self, message: str):
        """Print debug messages if debug is enabled."""
        if self.debug:
            print(f"[APIFuzzer] {message}")
            
    def _init_system_prompt(self):
        """Set the default system prompt focused on API payload generation."""
        self.system_prompt = """You analyze API responses and generate optimized JSON payloads for the next request.

Focus on:
1. Understanding error messages and API hints
2. Constructing valid JSON payloads based on the API's feedback
3. Iteratively refining payloads based on responses
4. Identifying parameter requirements, types, and constraints
5. The param names. The values are not very important as the api will tell us when we have a bad value. But on bad param name, it will return 400 error and tell us nothing useful. 
6. Don't add too many params at once. Always add one by one, so you can understand and reason on the response.
7. There is no need to try our initial starting point. So every next attempt should be a fresh attempt and not a fallback
8. Our initial params should be left untouched. They are fine. You can only add new ones.

For each response, create a JSON payload with:
- Fields that satisfy the requirements in error messages
- Appropriate data types for each field
- Consideration of validation errors mentioned

In case of 400 error, your parameter naming is wrong. Don't fall back. Try the next attempt based on our initial error (our start). That could be a case sensitive parameter. (In snake, camel, kebab or other casing).
Fields can be different datatypes. They can be strings, integers, arrays, objects so trying them in that order is the best approach.

Your output must be valid JSON without any explanation outside the JSON structure.
Include 'reasoning' field explaining your choices."""

        # Inject custom context if provided
        if self.custom_context:
            self.system_prompt += f"\n\nCUSTOM CONTEXT:\n{self.custom_context}"

    def set_context(self, context: dict):
        """
        Set additional context about the API.
        
        Args:
            context: Dict containing API context (endpoints, known parameters, etc.)
        """
        self.context = context
        
        # Add context to system prompt if it contains useful information
        if context:
            context_str = json.dumps(context, indent=2)
            self.system_prompt += f"\n\nAPI CONTEXT:\n{context_str}"
            
    def next_payload(self, api_response, current_payload = None):
        """
        Generate the next API payload based on the current response.
        
        Args:
            api_response: The API response to analyze (dict or JSON string)
            current_payload: The payload that generated this response (optional)
            
        Returns:
            A new JSON payload for the next request
        """
        # Normalize api_response to dict
        if isinstance(api_response, str):
            try:
                api_response = json.loads(api_response)
            except json.JSONDecodeError:
                api_response = {"raw_response": api_response}
                
        # Add this interaction to history
        interaction = {
            "response": api_response
        }
        
        if current_payload:
            interaction["request"] = current_payload
            
        self.history.append(interaction)
        
        # Prepare the message for the AI
        user_message = self._prepare_user_message(api_response, current_payload)
        
        # Get AI suggestion
        ai_response = self._get_ai_response(user_message)
        
        # Extract the payload from AI response
        try:
            # Try to parse the entire response as JSON
            payload = json.loads(ai_response)
            return payload
        except json.JSONDecodeError:
            # Try to extract JSON from the response
            self._log("Failed to parse entire response as JSON, trying to extract JSON")
            try:
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_content = ai_response[json_start:json_end]
                    return json.loads(json_content)
            except:
                # If all else fails, return a simple error payload
                self._log("Failed to extract valid JSON from AI response")
                return {
                    "error": "Failed to generate valid payload",
                    "raw_ai_response": ai_response[:200] + ("..." if len(ai_response) > 200 else "")
                }
    
    def _prepare_user_message(self, api_response, current_payload):
        """Prepare the user message for the AI."""
        message = "API Response:\n"
        message += json.dumps(api_response, indent=2)
        
        if current_payload:
            message += "\n\nCurrent Payload:\n"
            message += json.dumps(current_payload, indent=2)
            
        # Add history context if we have multiple interactions
        if len(self.history) >= 2:
            message += "\n\nBased on this response and previous interactions, "
        else:
            message += "\n\nBased on this response, "
            
        message += "generate an improved JSON payload for the next request. Include a 'reasoning' field explaining your choices. 400 errors usually are not descriptive, so if you get a 400 error, try to remove parameters or ensure case sensitive attempts. Too many params or wrong params will give 400 errors on this api. We need 500 errors (so we see error description) or we need to achieve a 200 OKAY! Parameters can be case sensitive. The error given by 500 errors is usually very descriptive of the issue at hand. Using that as our source of truth or grounding is the way to find the correct payload."
        return message
            
    def _get_ai_response(self, user_message):
        """Get a response from the AI model."""
        self._log("Requesting AI suggestion")
        
        # Prepare the messages
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_message}
        ]
        
        # Prepare the request
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://fuzz.adnansecurity.com"
        }
        
        data = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.3  # Lower temperature for more focused responses
        }
        
        # Make the request
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code != 200:
                self._log(f"API error: {response.status_code} - {response.text}")
                return json.dumps({
                    "error": f"API error {response.status_code}",
                    "reasoning": "Failed to get AI suggestion"
                })
                
            # Extract the content
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            self._log(f"Received AI suggestion")
            return content
            
        except Exception as e:
            self._log(f"Error getting AI suggestion: {str(e)}")
            return json.dumps({
                "error": "Failed to get AI suggestion",
                "reasoning": str(e)
            })
            
    def clear_history(self):
        """Clear the interaction history."""
        self.history = []
        
    def get_history(self):
        """Get the interaction history."""
        return self.history

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UniversalAPIFuzzer:
    """
    Universal API Fuzzer with AI-powered adaptive payload generation.
    Works with any REST API endpoint.
    """
    
    def __init__(self, base_url=None, use_burp=False, custom_headers=None, custom_context=None):
        """
        Initialize the Universal API Fuzzer.
        
        Args:
            base_url: Base URL for the API (optional, can use full URLs instead)
            use_burp: Whether to proxy requests through Burp Suite
            custom_headers: Dict of custom headers to include in all requests
            custom_context: Custom context string for AI fuzzer
        """
        self.session = requests.Session()
        self.base_url = base_url.rstrip('/') if base_url else None
        self.custom_headers = custom_headers or {}
        
        # Proxy setup
        if use_burp:
            self.proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
            self.session.verify = False
            print("🔄 Using Burp proxy: 127.0.0.1:8080")
        else:
            self.proxies = None
            
        # Initialize AI fuzzer
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            print("⚠️ Warning: OPENROUTER_API_KEY environment variable not set.")
            print("   AI-powered fuzzing will not be available.")
            self.fuzzer_available = False
        else:
            try:
                self.fuzzer = APIFuzzer(api_key=api_key, debug=True, custom_context=custom_context)
                self.fuzzer_available = True
                print("✅ AI Fuzzer initialized successfully")
                if custom_context:
                    print(f"📝 Custom context loaded: {custom_context[:100]}{'...' if len(custom_context) > 100 else ''}")
            except Exception as e:
                print(f"❌ Failed to initialize AI Fuzzer: {e}")
                self.fuzzer_available = False
        
        # For storing successful payloads
        self.successful_payloads = []

    def init(self):
        """Initialize fuzzer - placeholder for future authentication support"""
        print("🚀 Universal AI-Powered API Fuzzer")
        print("✅ Fuzzer ready")
        return True

    def extract_endpoint_context(self, url):
        """
        Analyze the URL to extract context for the fuzzer.
        This is used to provide endpoint-specific information to the AI.
        """
        parsed = urlparse(url)
        path = parsed.path
        
        context = {
            "url": url,
            "domain": parsed.netloc,
            "path": path,
            "url_structure": {}
        }
        
        # Extract path components
        path_parts = path.strip('/').split('/')
        if len(path_parts) > 0:
            # Look for version numbers
            for part in path_parts:
                if part.startswith('v') and len(part) <= 3 and part[1:].isdigit():
                    context["url_structure"]["version"] = part
                    
            # Look for common resource identifiers
            resource_patterns = {
                r'users?\/([^\/]+)': {"resource": "user"},
                r'accounts?\/([^\/]+)': {"resource": "account"},
                r'customers?\/([^\/]+)': {"resource": "customer"},
                r'orders?\/([^\/]+)': {"resource": "order"},
                r'products?\/([^\/]+)': {"resource": "product"},
                r'items?\/([^\/]+)': {"resource": "item"},
                r'transactions?\/([^\/]+)': {"resource": "transaction"},
                r'payments?\/([^\/]+)': {"resource": "payment"},
                r'invoices?\/([^\/]+)': {"resource": "invoice"},
            }
            
            endpoint_str = '/'.join(path_parts)
            for pattern, info in resource_patterns.items():
                match = re.search(pattern, endpoint_str, re.IGNORECASE)
                if match:
                    context["url_structure"]["resource_type"] = info["resource"]
                    context["url_structure"]["id_value"] = match.group(1)
            
            # Look for action identifiers
            common_actions = ["create", "update", "delete", "get", "list", "search", 
                            "activate", "deactivate", "cancel", "confirm", "validate",
                            "submit", "process", "approve", "reject"]
            last_part = path_parts[-1].lower() if path_parts else ""
            for action in common_actions:
                if action in last_part:
                    context["url_structure"]["action"] = action
                    break
                    
        return context

    def test_endpoint(self, url, methods=['GET', 'POST']):
        """
        Test a single endpoint with specified HTTP methods.
        
        Args:
            url: Full URL to test
            methods: List of HTTP methods to test (default: GET and POST)
        """
        print(f"\n🎯 Testing: {url}")
        
        results = {}
        
        for method in methods:
            print(f"📡 {method} request...")
            if method.upper() == 'GET':
                result = self.make_request(url, 'GET')
            elif method.upper() == 'POST':
                result = self.make_request(url, 'POST', {})
            elif method.upper() == 'PUT':
                result = self.make_request(url, 'PUT', {})
            elif method.upper() == 'DELETE':
                result = self.make_request(url, 'DELETE')
            elif method.upper() == 'PATCH':
                result = self.make_request(url, 'PATCH', {})
            else:
                print(f"   Unsupported method: {method}")
                continue
                
            results[method.upper()] = result
            print(f"   {method}: {result['status']} {result.get('reason', '')}")
        
        # Results summary
        print(f"\n� RESULTS:")
        for method, result in results.items():
            print(f"   {method}: {result['status']} {result.get('reason', '')}")
            
            # Check for interesting responses
            if result['status'] >= 200 and result['status'] < 300:
                print(f"      ✅ Success response")
            elif result['status'] >= 500:
                print(f"      ⚠️ Server error - potential vulnerability")
                
        return results

    def fuzz_endpoint(self, url, iterations=5, method='POST', initial_payload=None):
        """
        Continuously fuzz an endpoint using AI-based payload generation.
        
        Args:
            url: Full URL to test
            iterations: Number of iterations to run
            method: HTTP method to use ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
            initial_payload: Starting payload (optional)
        """
        if not self.fuzzer_available:
            print("❌ AI Fuzzer not available. Please set OPENROUTER_API_KEY.")
            return
            
        print(f"\n🔄 Starting AI-powered fuzzing on: {url}")
        print(f"   Method: {method}, Iterations: {iterations}")
        
        # Extract context from the URL
        endpoint_context = self.extract_endpoint_context(url)
        print("\n📊 Endpoint Context Analysis:")
        print(json.dumps(endpoint_context, indent=2))
        
        # Initialize fuzzer context
        fuzzer_context = {
            "api_endpoint": url,
            "authentication": "Custom headers: " + str(list(self.custom_headers.keys())) if self.custom_headers else "None",
            "general_patterns": {
                "error_format": "usually includes status, message and sometimes details"
            },
            "endpoint_specific": endpoint_context
        }
        
        self.fuzzer.set_context(fuzzer_context)
        
        # Set initial payload - always start with empty payload unless explicitly provided
        if initial_payload is None:
            current_payload = {}
            print("\n🧩 Starting with empty payload {} to trigger informative errors")
        else:
            current_payload = initial_payload
            print("\n🧩 Using provided initial payload:")
            print(json.dumps(current_payload, indent=2))
        
        # Fuzzing loop
        for i in range(iterations):
            print(f"\n{'='*50}")
            print(f"🔄 FUZZING ITERATION {i+1}/{iterations}")
            print(f"{'='*50}")
            
            # Print current payload
            print(f"📡 {method} request with payload:")
            print(json.dumps(current_payload, indent=2))
            
            # Make the request with current payload
            start_time = time.time()
            result = self.make_request(url, method, current_payload if method.upper() in ['POST', 'PUT', 'PATCH'] else None)
            request_time = time.time() - start_time
            
            # Check for interesting responses
            is_interesting = False
            if result['status'] >= 200 and result['status'] < 300:
                print("🎯 SUCCESS: Got a successful response!")
                is_interesting = True
            elif result['status'] >= 500:
                print("⚠️ INTERESTING: Got a server error - possible vulnerability!")
                is_interesting = True
            elif result['status'] == 400 and "missing" in str(result['body']).lower():
                print("📝 INTERESTING: Got details about missing parameters")
                is_interesting = True
            elif "permission" in str(result).lower() or "unauthorized" in str(result).lower():
                print("🚪 INFORMATIVE: Permission-related response detected")
                is_interesting = True
                
            # Print response details
            print(f"📥 Response ({result['status']} {result.get('reason', '')}) in {request_time:.2f}s:")
            if isinstance(result['body'], dict):
                print(json.dumps(result['body'], indent=2))
            else:
                # Try to pretty-print if it might be JSON
                try:
                    json_body = json.loads(result['body'])
                    print(json.dumps(json_body, indent=2))
                except:
                    # Just print the first part if it's long
                    body_str = str(result['body'])
                    if len(body_str) > 500:
                        print(f"{body_str[:500]}... [truncated, {len(body_str)} chars total]")
                    else:
                        print(body_str)
            
            # Save interesting results
            if is_interesting:
                self.successful_payloads.append({
                    "url": url,
                    "method": method,
                    "payload": current_payload,
                    "response": {
                        "status": result['status'],
                        "reason": result.get('reason', ''),
                        "body": result['body']
                    },
                    "iteration": i+1,
                    "timestamp": datetime.now().isoformat()
                })
                print("💾 Saved interesting result!")
            
            # Skip fuzzing if this is the last iteration
            if i >= iterations - 1:
                break
                
            # Generate next payload using APIFuzzer
            print("\n🧠 Generating next payload...")
            next_payload = self.fuzzer.next_payload(result['body'], current_payload)
            
            # Extract the payload without the reasoning field
            if isinstance(next_payload, dict) and "reasoning" in next_payload:
                print(f"💡 AI Reasoning: {next_payload['reasoning']}")
                reasoning = next_payload.pop("reasoning")  # Remove and store reasoning
            
            print(f"📝 Next payload generated:")
            print(json.dumps(next_payload, indent=2))
            
            # Update the current payload for next iteration
            current_payload = next_payload
            
            # Add a small delay between requests to avoid rate limiting
            time.sleep(random.uniform(1.5, 3.0))
            
        # Save results at the end
        if self.successful_payloads:
            filename = f"api_fuzzing_results_{int(time.time())}.json"
            with open(filename, "w") as f:
                json.dump(self.successful_payloads, f, indent=2)
            print(f"\n💾 Saved {len(self.successful_payloads)} interesting results to {filename}")
            
        print(f"\n✅ Completed {iterations} fuzzing iterations on {url}")
        return

    def make_request(self, url, method, payload=None):
        """
        Make an HTTP request to the specified URL.
        
        Args:
            url: Full URL to request
            method: HTTP method (GET, POST, PUT, DELETE, PATCH)
            payload: Request payload for POST/PUT/PATCH (optional)
            
        Returns:
            Dict with status, reason, and body
        """
        try:
            # Prepare headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
                'Accept': 'application/json, */*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/json',
            }
            
            # Add custom headers
            headers.update(self.custom_headers)
            
            # Add content length for POST/PUT/PATCH
            if payload and method.upper() in ['POST', 'PUT', 'PATCH']:
                payload_json = json.dumps(payload)
                headers['Content-Length'] = str(len(payload_json))
            
            # Make the request
            method = method.upper()
            if method == 'GET':
                response = self.session.get(url, headers=headers, proxies=self.proxies, timeout=20)
            elif method == 'POST':
                response = self.session.post(url, json=payload, headers=headers, proxies=self.proxies, timeout=20)
            elif method == 'PUT':
                response = self.session.put(url, json=payload, headers=headers, proxies=self.proxies, timeout=20)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=headers, proxies=self.proxies, timeout=20)
            elif method == 'PATCH':
                response = self.session.patch(url, json=payload, headers=headers, proxies=self.proxies, timeout=20)
            else:
                return {'status': 0, 'error': f'Unsupported method: {method}', 'body': {'error': f'Unsupported method: {method}'}}
                
            print(f"   {method} {url}: {response.status_code}")
            
            # Parse response body
            try:
                body = response.json()
            except:
                body = response.text
                
            return {'status': response.status_code, 'reason': response.reason, 'body': body}
            
        except Exception as e:
            print(f"   ❌ {method} request failed: {e}")
            return {'status': 0, 'error': str(e), 'body': {'error': str(e)}}


def main():
    parser = argparse.ArgumentParser(
        description="Universal AI-Powered API Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic fuzzing with full URL
  python3 aifuzzer.py https://api.example.com/v1/users/123/profile
  
  # With custom authorization header
  python3 aifuzzer.py https://api.example.com/v1/users -H "Authorization: Bearer YOUR_TOKEN"
  
  # Multiple custom headers
  python3 aifuzzer.py https://api.example.com/v1/data -H "X-API-Key: key123" -H "X-Session: sess456"
  
  # With custom context for better AI understanding
  python3 aifuzzer.py https://api.example.com/v1/orders -c "This endpoint requires order ID and billing information"
  
  # With context from file
  python3 aifuzzer.py https://api.example.com/v1/payment --context-file context.txt
  
  # Single test mode (no fuzzing)
  python3 aifuzzer.py https://api.example.com/v1/status -s
  
  # Test multiple HTTP methods
  python3 aifuzzer.py https://api.example.com/v1/resource -m POST PUT DELETE
  
  # With Burp Suite proxy for inspection
  python3 aifuzzer.py https://api.example.com/v1/data -b --burp-port 8080

Academic Citation:
  This tool represents the world's first production AI-based adaptive API fuzzer,
  utilizing large language models to dynamically generate and refine payloads
  based on real-time API feedback. Developed by Adnan Ahmad, Adnan Security Inc., 2024-2025.
        """
    )
    parser.add_argument("url", help="Full URL to test (e.g., https://api.example.com/v1/users/123)")
    parser.add_argument("-i", "--iterations", type=int, default=10, 
                       help="Number of fuzzing iterations (default: 10)")
    parser.add_argument("-m", "--methods", nargs='+', default=["POST"],
                       choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
                       help="HTTP methods to use (default: POST)")
    parser.add_argument("-b", "--burp", action="store_true", 
                       help="Use Burp proxy for request inspection")
    parser.add_argument("--burp-port", type=int, default=8080,
                       help="Burp proxy port (default: 8080)")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header in format 'Name: Value' (can be used multiple times)")
    parser.add_argument("-p", "--payload", 
                       help="Initial JSON payload (optional, default: empty {})")
    parser.add_argument("-s", "--single", action="store_true", 
                       help="Single test only, no fuzzing")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Verbose output")
    parser.add_argument("-c", "--context", 
                       help="Custom context to inject into AI system prompt (optional)")
    parser.add_argument("--context-file", 
                       help="File containing custom context to inject into AI system prompt (optional)")
    parser.add_argument("--base-url",
                       help="Base URL if you want to provide relative paths later (optional)")
    
    args = parser.parse_args()
    
    # Validate URL
    parsed_url = urlparse(args.url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"❌ Invalid URL: {args.url}")
        print("   URL must include scheme (http:// or https://) and domain")
        return
    
    # Parse custom headers
    custom_headers = {}
    if args.headers:
        for header in args.headers:
            if ':' not in header:
                print(f"❌ Invalid header format: {header}")
                print("   Headers must be in format 'Name: Value'")
                return
            name, value = header.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        print(f"✅ Loaded {len(custom_headers)} custom header(s)")
    
    # Load custom context
    custom_context = args.context
    if args.context_file:
        try:
            with open(args.context_file, 'r') as f:
                file_context = f.read().strip()
                if custom_context:
                    custom_context = f"{custom_context}\n\n{file_context}"
                else:
                    custom_context = file_context
            print(f"📁 Loaded context from file: {args.context_file}")
        except Exception as e:
            print(f"❌ Failed to load context file {args.context_file}: {e}")
            return
    
    # Update proxy port if using Burp
    if args.burp and args.burp_port != 8080:
        print(f"🔄 Using Burp proxy on port: {args.burp_port}")
    
    # Initialize fuzzer
    fuzzer = UniversalAPIFuzzer(
        base_url=args.base_url,
        use_burp=args.burp,
        custom_headers=custom_headers,
        custom_context=custom_context
    )
    
    # Update proxy port if needed
    if args.burp and args.burp_port != 8080:
        fuzzer.proxies = {
            'http': f'http://127.0.0.1:{args.burp_port}',
            'https': f'http://127.0.0.1:{args.burp_port}'
        }
    
    # Initialize
    if fuzzer.init():
        if args.single:
            # Run a single test without fuzzing
            print("🧪 Running single test mode (no fuzzing)")
            fuzzer.test_endpoint(args.url, methods=args.methods)
        else:
            # Parse initial payload if provided
            initial_payload = None
            if args.payload:
                try:
                    initial_payload = json.loads(args.payload)
                    print(f"✅ Using provided initial payload: {json.dumps(initial_payload, indent=2)}")
                except json.JSONDecodeError:
                    print(f"❌ Failed to parse payload JSON: {args.payload}")
                    return
            
            # Run continuous fuzzing for each method
            for method in args.methods:
                fuzzer.fuzz_endpoint(
                    args.url,
                    iterations=args.iterations,
                    method=method,
                    initial_payload=initial_payload
                )
    else:
        print("❌ Failed to initialize fuzzer")

if __name__ == "__main__":
    main()