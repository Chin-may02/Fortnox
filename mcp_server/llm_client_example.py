#!/usr/bin/env python3
"""
Example MCP Client for LLM Email Classification
Demonstrates how to use the LLM-based MCP server.
"""

import json
import sys
import subprocess
from typing import Dict, Any, Optional


class LLMEmailClassifierMCPClient:
    """Client for interacting with the LLM email classification MCP server"""

    def __init__(self, server_path: str):
        """Initialize the MCP client"""
        self.server_path = server_path
        self.process = None
        self.request_id = 0

    def start_server(self):
        """Start the MCP server process"""
        print(f"Starting LLM MCP server: {self.server_path}")
        self.process = subprocess.Popen(
            [sys.executable, self.server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        print("✓ Server started successfully")

        # Initialize the server
        self._send_request("initialize", {
            "protocolVersion": "0.1.0",
            "capabilities": {},
            "clientInfo": {
                "name": "llm-email-classifier-client",
                "version": "2.0.0"
            }
        })

    def stop_server(self):
        """Stop the MCP server process"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            print("✓ Server stopped")

    def _send_request(self, method: str, params: Optional[Dict] = None) -> Dict:
        """Send a JSON-RPC request to the server"""
        self.request_id += 1

        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method
        }

        if params:
            request["params"] = params

        # Send request
        request_json = json.dumps(request) + "\n"
        self.process.stdin.write(request_json)
        self.process.stdin.flush()

        # Read response
        response_line = self.process.stdout.readline()
        response = json.loads(response_line)

        if "error" in response:
            raise Exception(f"Server error: {response['error']}")

        return response.get("result", {})

    def list_tools(self) -> Dict:
        """List available tools"""
        return self._send_request("tools/list")

    def classify_email(self, subject: str, body: str, sender: str,
                      headers: Optional[Dict] = None,
                      links: Optional[list] = None) -> Dict:
        """Classify a single email using LLM"""
        arguments = {
            "subject": subject,
            "body": body,
            "sender": sender
        }

        if headers:
            arguments["headers"] = headers
        if links:
            arguments["links"] = links

        params = {
            "name": "classify_email",
            "arguments": arguments
        }

        return self._send_request("tools/call", params)

    def analyze_email_batch(self, emails: list) -> Dict:
        """Classify multiple emails in batch"""
        params = {
            "name": "analyze_email_batch",
            "arguments": {
                "emails": emails
            }
        }

        return self._send_request("tools/call", params)


def print_classification_result(result: Dict, email_num: Optional[int] = None):
    """Pretty print classification result"""
    if email_num:
        print(f"\n{'=' * 70}")
        print(f"EMAIL {email_num} RESULT")
        print('=' * 70)
    else:
        print("\n" + "=" * 70)
        print("CLASSIFICATION RESULT")
        print("=" * 70)

    if "error" in result:
        print(f"❌ Error: {result['error']}")
        return

    print(f"Classification: {result.get('classification', 'N/A').upper()}")
    print(f"Confidence: {result.get('confidence', 0):.1%}")
    print(f"Risk Level: {result.get('risk_level', 'N/A')}")
    print(f"Method: {result.get('method', 'N/A')}")
    print(f"Provider: {result.get('provider', 'N/A')}")
    print(f"Model: {result.get('model', 'N/A')}")

    if result.get('reasoning'):
        print(f"\n🤔 AI Reasoning:")
        print(f"   {result['reasoning']}")

    if result.get('risk_indicators'):
        print(f"\n⚠️  Risk Indicators:")
        for indicator in result['risk_indicators']:
            print(f"   • {indicator}")

    if result.get('recommendations'):
        print(f"\n💡 Recommendations:")
        print(f"   {result['recommendations']}")

    print("=" * 70)


def main():
    """Main function with example usage"""
    import os

    # Path to the LLM MCP server script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(script_dir, 'llm_email_mcp_server.py')

    print("=" * 70)
    print("LLM EMAIL CLASSIFICATION MCP CLIENT DEMO")
    print("=" * 70)
    print("\nThis uses REAL AI (Claude or GPT) for email classification")
    print("Make sure you have set your API key in .env file or environment")

    # Check for API keys
    if not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        print("\n❌ ERROR: No API keys found!")
        print("\nPlease set one of the following in your .env file:")
        print("  ANTHROPIC_API_KEY=your-key-here  # For Claude/Anthropic")
        print("  OPENAI_API_KEY=your-key-here     # For OpenAI/GPT")
        print("\nYou can also set LLM_PROVIDER=anthropic or openai")
        sys.exit(1)

    # Create client
    client = LLMEmailClassifierMCPClient(server_path)

    try:
        # Start server
        client.start_server()

        # List available tools
        print("\n" + "=" * 70)
        print("LISTING AVAILABLE MCP TOOLS")
        print("=" * 70)
        tools = client.list_tools()
        print(f"Available tools: {len(tools.get('tools', []))}")
        for tool in tools.get('tools', []):
            print(f"\n📧 {tool['name']}")
            print(f"   {tool['description'][:100]}...")

        # Example 1: Classify a legitimate email
        print("\n" + "=" * 70)
        print("EXAMPLE 1: Legitimate Business Email")
        print("=" * 70)

        result1 = client.classify_email(
            subject="Q4 Project Status Update",
            body="Hi team, Please find attached the Q4 project status report. We're on track to meet all deliverables. Let me know if you have questions.",
            sender="manager@company.com"
        )
        print_classification_result(result1)

        # Example 2: Classify a phishing email
        print("\n" + "=" * 70)
        print("EXAMPLE 2: Phishing Email")
        print("=" * 70)

        result2 = client.classify_email(
            subject="URGENT: Your Account Will Be Closed!",
            body="Dear customer, We detected suspicious activity on your account. Your account will be permanently closed within 24 hours unless you verify your identity immediately. Click this link to verify: http://192.168.1.1/verify-now.php",
            sender="security@paypal-verify.tk",
            links=["http://192.168.1.1/verify-now.php"]
        )
        print_classification_result(result2)

        # Example 3: Classify a spam email
        print("\n" + "=" * 70)
        print("EXAMPLE 3: Spam Email")
        print("=" * 70)

        result3 = client.classify_email(
            subject="🎉 CONGRATULATIONS! You've Won $10,000!!!",
            body="Dear lucky winner! You have been selected to receive $10,000 in our exclusive promotion! Click here NOW to claim your prize before it expires! This offer is 100% FREE and GUARANTEED!",
            sender="prizes@winner-rewards.xyz"
        )
        print_classification_result(result3)

        print("\n" + "=" * 70)
        print("✅ DEMO COMPLETE")
        print("=" * 70)
        print("\n🎉 All emails analyzed using REAL AI (not traditional ML)!")
        print("💡 The LLM provides reasoning and specific risk indicators")
        print("🛡️  This is TRUE Model Context Protocol implementation")

    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    finally:
        # Stop server
        client.stop_server()


if __name__ == "__main__":
    main()
