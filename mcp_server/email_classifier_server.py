#!/usr/bin/env python3
"""
MCP (Model Context Protocol) Server for Email Classification
Provides tools to read and classify emails as phishing, malicious, spam, or legitimate.
"""

import json
import sys
import asyncio
from typing import Any, Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EmailClassifierMCPServer:
    """MCP Server for email classification using JSON-RPC protocol"""

    def __init__(self):
        self.classifier = None
        self.request_id = 0

    async def initialize(self):
        """Initialize the email classifier model"""
        try:
            # Import here to avoid issues if dependencies aren't available
            from email_classifier import EmailClassifier
            self.classifier = EmailClassifier()
            await self.classifier.load_model()
            logger.info("Email classifier initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize email classifier: {e}")
            raise

    def _create_response(self, request_id: Any, result: Any = None, error: Optional[Dict] = None) -> Dict:
        """Create a JSON-RPC response"""
        response = {
            "jsonrpc": "2.0",
            "id": request_id
        }
        if error:
            response["error"] = error
        else:
            response["result"] = result
        return response

    def _create_error(self, code: int, message: str, data: Any = None) -> Dict:
        """Create a JSON-RPC error object"""
        error = {
            "code": code,
            "message": message
        }
        if data:
            error["data"] = data
        return error

    async def handle_list_tools(self, request_id: Any) -> Dict:
        """Handle tools/list request - return available tools"""
        tools = [
            {
                "name": "classify_email",
                "description": "Classify an email as phishing, malicious, spam, or legitimate. Analyzes email content, subject, sender, and other features to determine the email's classification.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subject": {
                            "type": "string",
                            "description": "The email subject line"
                        },
                        "body": {
                            "type": "string",
                            "description": "The email body content (plain text or HTML)"
                        },
                        "sender": {
                            "type": "string",
                            "description": "The sender's email address"
                        },
                        "headers": {
                            "type": "object",
                            "description": "Optional email headers (From, To, Reply-To, etc.)",
                            "additionalProperties": {"type": "string"}
                        },
                        "links": {
                            "type": "array",
                            "description": "Optional list of URLs found in the email",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["subject", "body", "sender"]
                }
            },
            {
                "name": "analyze_email_batch",
                "description": "Classify multiple emails in batch for efficiency. Returns classification results for all provided emails.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "emails": {
                            "type": "array",
                            "description": "Array of email objects to classify",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "subject": {"type": "string"},
                                    "body": {"type": "string"},
                                    "sender": {"type": "string"},
                                    "headers": {
                                        "type": "object",
                                        "additionalProperties": {"type": "string"}
                                    },
                                    "links": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    }
                                },
                                "required": ["subject", "body", "sender"]
                            }
                        }
                    },
                    "required": ["emails"]
                }
            }
        ]
        return self._create_response(request_id, {"tools": tools})

    async def handle_call_tool(self, request_id: Any, tool_name: str, arguments: Dict) -> Dict:
        """Handle tools/call request - execute a tool"""
        try:
            if tool_name == "classify_email":
                result = await self._classify_email(arguments)
                return self._create_response(request_id, result)
            elif tool_name == "analyze_email_batch":
                result = await self._analyze_email_batch(arguments)
                return self._create_response(request_id, result)
            else:
                error = self._create_error(-32601, f"Tool not found: {tool_name}")
                return self._create_response(request_id, error=error)
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}", exc_info=True)
            error = self._create_error(-32603, f"Internal error: {str(e)}")
            return self._create_response(request_id, error=error)

    async def _classify_email(self, arguments: Dict) -> Dict:
        """Classify a single email"""
        subject = arguments.get("subject", "")
        body = arguments.get("body", "")
        sender = arguments.get("sender", "")
        headers = arguments.get("headers", {})
        links = arguments.get("links", [])

        if not self.classifier:
            return {
                "error": "Classifier not initialized",
                "classification": "unknown",
                "confidence": 0.0
            }

        # Perform classification
        result = await self.classifier.classify(
            subject=subject,
            body=body,
            sender=sender,
            headers=headers,
            links=links
        )

        return result

    async def _analyze_email_batch(self, arguments: Dict) -> Dict:
        """Classify multiple emails in batch"""
        emails = arguments.get("emails", [])

        if not self.classifier:
            return {
                "error": "Classifier not initialized",
                "results": []
            }

        results = []
        for email in emails:
            result = await self._classify_email(email)
            results.append(result)

        return {
            "count": len(results),
            "results": results
        }

    async def handle_request(self, request: Dict) -> Dict:
        """Handle incoming JSON-RPC request"""
        try:
            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            if method == "initialize":
                # Client initialization
                return self._create_response(request_id, {
                    "protocolVersion": "0.1.0",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "email-classifier-mcp-server",
                        "version": "1.0.0"
                    }
                })
            elif method == "tools/list":
                return await self.handle_list_tools(request_id)
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                return await self.handle_call_tool(request_id, tool_name, arguments)
            else:
                error = self._create_error(-32601, f"Method not found: {method}")
                return self._create_response(request_id, error=error)
        except Exception as e:
            logger.error(f"Error handling request: {e}", exc_info=True)
            error = self._create_error(-32603, f"Internal error: {str(e)}")
            return self._create_response(request.get("id"), error=error)

    async def run(self):
        """Run the MCP server - read from stdin, write to stdout"""
        logger.info("Starting Email Classifier MCP Server...")

        try:
            await self.initialize()
        except Exception as e:
            logger.error(f"Failed to initialize: {e}")
            sys.exit(1)

        logger.info("Server ready, waiting for requests...")

        # Read JSON-RPC requests from stdin
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                request = json.loads(line)
                response = await self.handle_request(request)

                # Write response to stdout
                print(json.dumps(response), flush=True)

            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON received: {e}")
                error_response = self._create_response(None, error=self._create_error(-32700, "Parse error"))
                print(json.dumps(error_response), flush=True)
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                break


async def main():
    """Main entry point"""
    server = EmailClassifierMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
