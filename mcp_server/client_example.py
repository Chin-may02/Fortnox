#!/usr/bin/env python3
"""
MCP Client for Email Classification
Example client to interact with the email classification MCP server.
"""

import json
import sys
import subprocess
from typing import Dict, Any, Optional


class EmailClassifierMCPClient:
    """Client for interacting with the email classification MCP server"""

    def __init__(self, server_path: str):
        """Initialize the MCP client"""
        self.server_path = server_path
        self.process = None
        self.request_id = 0

    def start_server(self):
        """Start the MCP server process"""
        print(f"Starting MCP server: {self.server_path}")
        self.process = subprocess.Popen(
            [sys.executable, self.server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        print("Server started successfully")

        # Initialize the server
        self._send_request("initialize", {
            "protocolVersion": "0.1.0",
            "capabilities": {},
            "clientInfo": {
                "name": "email-classifier-client",
                "version": "1.0.0"
            }
        })

    def stop_server(self):
        """Stop the MCP server process"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            print("Server stopped")

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
        """Classify a single email"""
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


def print_classification_result(result: Dict):
    """Pretty print classification result"""
    print("\n" + "=" * 60)
    print("CLASSIFICATION RESULT")
    print("=" * 60)
    print(f"Classification: {result.get('classification', 'N/A').upper()}")
    print(f"Confidence: {result.get('confidence', 0):.2%}")
    print(f"Risk Level: {result.get('risk_level', 'N/A')}")

    if 'risk_scores' in result:
        print("\nRisk Scores:")
        for category, score in result['risk_scores'].items():
            print(f"  {category.capitalize()}: {score:.3f}")

    if 'probabilities' in result:
        print("\nProbabilities:")
        for category, prob in result['probabilities'].items():
            print(f"  {category.capitalize()}: {prob:.2%}")

    if 'warnings' in result and result['warnings']:
        print("\nWarnings:")
        for warning in result['warnings']:
            print(f"  ⚠ {warning}")

    print("=" * 60)


def main():
    """Main function with example usage"""
    import os

    # Path to the MCP server script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(script_dir, 'email_classifier_server.py')

    print("=" * 60)
    print("EMAIL CLASSIFICATION MCP CLIENT")
    print("=" * 60)

    # Create client
    client = EmailClassifierMCPClient(server_path)

    try:
        # Start server
        client.start_server()

        # List available tools
        print("\nListing available tools...")
        tools = client.list_tools()
        print(f"Available tools: {len(tools.get('tools', []))}")
        for tool in tools.get('tools', []):
            print(f"  - {tool['name']}: {tool['description'][:60]}...")

        # Example 1: Classify a legitimate email
        print("\n" + "=" * 60)
        print("EXAMPLE 1: Legitimate Email")
        print("=" * 60)

        result1 = client.classify_email(
            subject="Team meeting tomorrow at 2 PM",
            body="Hi team, just a reminder about our project meeting tomorrow at 2 PM in conference room A. Please bring your status updates.",
            sender="manager@company.com"
        )
        print_classification_result(result1)

        # Example 2: Classify a phishing email
        print("\n" + "=" * 60)
        print("EXAMPLE 2: Phishing Email")
        print("=" * 60)

        result2 = client.classify_email(
            subject="URGENT: Verify your account now!",
            body="Your account has been suspended due to unusual activity. Click here to verify your identity immediately: http://192.168.1.1/verify",
            sender="security@paypa1.com",
            links=["http://192.168.1.1/verify"]
        )
        print_classification_result(result2)

        # Example 3: Classify a spam email
        print("\n" + "=" * 60)
        print("EXAMPLE 3: Spam Email")
        print("=" * 60)

        result3 = client.classify_email(
            subject="Congratulations! You've won $1,000,000!!!",
            body="You are the lucky winner of our million dollar prize! Act now to claim your reward. No cost to you, 100% guaranteed!",
            sender="lottery@winner-prize.com"
        )
        print_classification_result(result3)

        # Example 4: Batch classification
        print("\n" + "=" * 60)
        print("EXAMPLE 4: Batch Classification")
        print("=" * 60)

        batch_emails = [
            {
                "subject": "Meeting notes from today",
                "body": "Hi all, please find attached the notes from today's meeting.",
                "sender": "colleague@company.com"
            },
            {
                "subject": "Your system has been infected!",
                "body": "Pay 1 Bitcoin to recover your files. Wallet: ABC123XYZ",
                "sender": "hacker@malicious.cc"
            }
        ]

        batch_result = client.analyze_email_batch(batch_emails)
        print(f"Processed {batch_result.get('count', 0)} emails")

        for i, result in enumerate(batch_result.get('results', []), 1):
            print(f"\n--- Email {i} ---")
            print(f"Classification: {result.get('classification', 'N/A').upper()}")
            print(f"Confidence: {result.get('confidence', 0):.2%}")
            print(f"Risk Level: {result.get('risk_level', 'N/A')}")

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    finally:
        # Stop server
        client.stop_server()

    print("\n" + "=" * 60)
    print("CLIENT DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
