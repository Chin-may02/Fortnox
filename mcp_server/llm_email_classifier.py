"""
LLM-Based Email Classifier
Uses actual LLM APIs (Claude/Anthropic, OpenAI) for intelligent email classification.
This is a TRUE AI-powered approach, not traditional ML.
"""

import os
import json
from typing import Dict, List, Optional, Literal
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class LLMEmailClassifier:
    """Email classifier using LLM APIs for intelligent analysis"""

    # Classification categories
    LEGITIMATE = "legitimate"
    SPAM = "spam"
    PHISHING = "phishing"
    MALICIOUS = "malicious"

    def __init__(self, provider: Literal["anthropic", "openai"] = "anthropic"):
        """
        Initialize the LLM-based email classifier

        Args:
            provider: LLM provider to use ("anthropic" or "openai")
        """
        self.provider = provider
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the LLM client based on provider"""
        if self.provider == "anthropic":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY not found in environment variables. "
                    "Please set it in .env file or environment."
                )
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=api_key)
                self.model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            except ImportError:
                raise ImportError(
                    "anthropic package not installed. "
                    "Install it with: pip install anthropic"
                )

        elif self.provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError(
                    "OPENAI_API_KEY not found in environment variables. "
                    "Please set it in .env file or environment."
                )
            try:
                import openai
                self.client = openai.OpenAI(api_key=api_key)
                self.model = os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
            except ImportError:
                raise ImportError(
                    "openai package not installed. "
                    "Install it with: pip install openai"
                )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def _create_classification_prompt(self, subject: str, body: str, sender: str,
                                     headers: Optional[Dict] = None,
                                     links: Optional[List[str]] = None) -> str:
        """Create a prompt for LLM to classify the email"""

        headers = headers or {}
        links = links or []

        prompt = f"""Analyze the following email and classify it into one of these categories:
- legitimate: Normal, safe email from a trusted source
- spam: Unsolicited bulk email, promotional content
- phishing: Attempt to steal credentials, impersonation, social engineering
- malicious: Contains malware threats, ransomware, extortion

Email Details:
Subject: {subject}
Sender: {sender}
Body:
{body}

"""

        if headers:
            prompt += f"\nHeaders:\n"
            for key, value in headers.items():
                prompt += f"{key}: {value}\n"

        if links:
            prompt += f"\nLinks found in email:\n"
            for link in links:
                prompt += f"- {link}\n"

        prompt += """
Please analyze this email carefully and provide your classification in JSON format:
{
    "classification": "legitimate|spam|phishing|malicious",
    "confidence": 0.0-1.0,
    "reasoning": "Brief explanation of your classification",
    "risk_indicators": ["list", "of", "specific", "red", "flags"],
    "recommendations": "What the recipient should do"
}

Respond ONLY with valid JSON, no additional text."""

        return prompt

    async def classify(self, subject: str, body: str, sender: str,
                      headers: Optional[Dict] = None,
                      links: Optional[List[str]] = None) -> Dict:
        """
        Classify an email using LLM API

        Args:
            subject: Email subject line
            body: Email body content
            sender: Sender email address
            headers: Optional email headers
            links: Optional list of URLs in the email

        Returns:
            Dictionary with classification results
        """

        prompt = self._create_classification_prompt(subject, body, sender, headers, links)

        try:
            if self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=1024,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )

                # Extract the text response
                response_text = response.content[0].text

            elif self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are an expert email security analyst."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=1024
                )

                response_text = response.choices[0].message.content

            # Parse the JSON response
            result = self._parse_llm_response(response_text)

            # Add metadata
            result["method"] = "llm-based"
            result["provider"] = self.provider
            result["model"] = self.model

            return result

        except Exception as e:
            # Fallback error response
            return {
                "classification": "unknown",
                "confidence": 0.0,
                "reasoning": f"Error during classification: {str(e)}",
                "risk_indicators": [],
                "recommendations": "Unable to classify. Manual review recommended.",
                "method": "llm-based",
                "provider": self.provider,
                "error": str(e)
            }

    def _parse_llm_response(self, response_text: str) -> Dict:
        """Parse the LLM's JSON response"""
        try:
            # Try to extract JSON from the response
            # Sometimes LLMs add markdown code blocks
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            elif "```" in response_text:
                json_start = response_text.find("```") + 3
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()

            result = json.loads(response_text)

            # Validate and normalize the result
            classification = result.get("classification", "unknown").lower()
            if classification not in [self.LEGITIMATE, self.SPAM, self.PHISHING, self.MALICIOUS]:
                classification = "unknown"

            confidence = float(result.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))  # Clamp to 0-1

            # Determine risk level based on classification and confidence
            if classification == self.LEGITIMATE:
                risk_level = "Low"
            elif confidence > 0.8:
                risk_level = "High"
            elif confidence > 0.5:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            return {
                "classification": classification,
                "confidence": confidence,
                "risk_level": risk_level,
                "reasoning": result.get("reasoning", ""),
                "risk_indicators": result.get("risk_indicators", []),
                "recommendations": result.get("recommendations", "")
            }

        except json.JSONDecodeError as e:
            # If JSON parsing fails, return the raw response
            return {
                "classification": "unknown",
                "confidence": 0.0,
                "risk_level": "Unknown",
                "reasoning": f"Failed to parse LLM response: {response_text[:200]}",
                "risk_indicators": [],
                "recommendations": "Manual review required",
                "parse_error": str(e)
            }

    async def classify_batch(self, emails: List[Dict]) -> List[Dict]:
        """
        Classify multiple emails

        Args:
            emails: List of email dictionaries with 'subject', 'body', 'sender', etc.

        Returns:
            List of classification results
        """
        results = []
        for email in emails:
            result = await self.classify(
                subject=email.get("subject", ""),
                body=email.get("body", ""),
                sender=email.get("sender", ""),
                headers=email.get("headers"),
                links=email.get("links")
            )
            results.append(result)

        return results
