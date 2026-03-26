"""
Tests for Email Classification MCP Server
"""

import unittest
import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mcp_server'))

from email_classifier import EmailClassifier


class TestEmailClassifier(unittest.TestCase):
    """Test cases for EmailClassifier"""

    def setUp(self):
        """Set up test fixtures"""
        self.classifier = EmailClassifier()

    def test_extract_features_legitimate(self):
        """Test feature extraction for legitimate email"""
        features = self.classifier.extract_email_features(
            subject="Team meeting tomorrow",
            body="Hi team, we have a meeting tomorrow at 10 AM. Please attend.",
            sender="manager@company.com"
        )

        self.assertIsInstance(features, dict)
        self.assertIn('subject_length', features)
        self.assertIn('body_length', features)
        self.assertIn('sender_length', features)
        self.assertEqual(features['subject_has_urgency'], 0)
        self.assertEqual(features['sender_brand_impersonation'], 0)

    def test_extract_features_phishing(self):
        """Test feature extraction for phishing email"""
        features = self.classifier.extract_email_features(
            subject="URGENT: Verify your PayPal account",
            body="Your account has been suspended. Click here to verify: http://192.168.1.1/verify",
            sender="security@paypal-verify.com",
            links=["http://192.168.1.1/verify"]
        )

        self.assertIsInstance(features, dict)
        self.assertEqual(features['subject_has_urgency'], 1)
        self.assertEqual(features['subject_has_security'], 1)
        self.assertEqual(features['sender_brand_impersonation'], 1)
        self.assertGreater(features['phishing_keyword_count'], 0)
        self.assertEqual(features['ip_url_count'], 1)

    def test_extract_features_spam(self):
        """Test feature extraction for spam email"""
        features = self.classifier.extract_email_features(
            subject="Congratulations! You've WON $1,000,000!!!",
            body="You are the lucky winner! Act now! Free money! Guaranteed!",
            sender="lottery@winner.com"
        )

        self.assertIsInstance(features, dict)
        self.assertEqual(features['subject_has_reward'], 1)
        self.assertGreater(features['spam_keyword_count'], 0)
        self.assertGreater(features['subject_all_caps_ratio'], 0)
        self.assertGreater(features['subject_exclamation_count'], 0)

    def test_extract_features_malicious(self):
        """Test feature extraction for malicious email"""
        features = self.classifier.extract_email_features(
            subject="Your computer is infected",
            body="Pay 1 Bitcoin to wallet ABC123 to recover your files. Ransomware detected.",
            sender="hacker@malicious.cc"
        )

        self.assertIsInstance(features, dict)
        self.assertGreater(features['malicious_keyword_count'], 0)
        self.assertEqual(features['sender_suspicious_tld'], 1)

    def test_calculate_entropy(self):
        """Test entropy calculation"""
        # High entropy (random)
        high_entropy = self.classifier._calculate_entropy("x3k9m2p8q1w5")
        # Low entropy (repeated)
        low_entropy = self.classifier._calculate_entropy("aaaaaaaaaa")

        self.assertGreater(high_entropy, low_entropy)

    def test_rule_based_classification_legitimate(self):
        """Test rule-based classification for legitimate email"""
        result = self.classifier._rule_based_classification(
            features={
                'phishing_keyword_count': 0,
                'spam_keyword_count': 0,
                'malicious_keyword_count': 0,
                'sender_brand_impersonation': 0,
                'subject_has_security': 0,
                'subject_has_reward': 0,
                'subject_all_caps_ratio': 0,
                'subject_exclamation_count': 0,
                'suspicious_url_count': 0,
                'ip_url_count': 0,
                'shortened_url_count': 0
            },
            subject="Team meeting",
            body="Hi team",
            sender="manager@company.com"
        )

        self.assertEqual(result['classification'], EmailClassifier.LEGITIMATE)
        self.assertEqual(result['method'], 'rule-based')
        self.assertIn('confidence', result)
        self.assertIn('risk_level', result)

    def test_rule_based_classification_phishing(self):
        """Test rule-based classification for phishing email"""
        result = self.classifier._rule_based_classification(
            features={
                'phishing_keyword_count': 5,
                'spam_keyword_count': 0,
                'malicious_keyword_count': 0,
                'sender_brand_impersonation': 1,
                'subject_has_security': 1,
                'subject_has_reward': 0,
                'subject_all_caps_ratio': 0,
                'subject_exclamation_count': 0,
                'suspicious_url_count': 1,
                'ip_url_count': 1,
                'shortened_url_count': 0
            },
            subject="URGENT: Verify account",
            body="Click here to verify",
            sender="security@paypa1.com"
        )

        self.assertEqual(result['classification'], EmailClassifier.PHISHING)
        self.assertGreater(result['confidence'], 0.5)

    def test_rule_based_classification_spam(self):
        """Test rule-based classification for spam email"""
        result = self.classifier._rule_based_classification(
            features={
                'phishing_keyword_count': 0,
                'spam_keyword_count': 5,
                'malicious_keyword_count': 0,
                'sender_brand_impersonation': 0,
                'subject_has_security': 0,
                'subject_has_reward': 1,
                'subject_all_caps_ratio': 0.8,
                'subject_exclamation_count': 3,
                'suspicious_url_count': 0,
                'ip_url_count': 0,
                'shortened_url_count': 0
            },
            subject="WIN $1M!!!",
            body="Free money!",
            sender="lottery@winner.com"
        )

        self.assertEqual(result['classification'], EmailClassifier.SPAM)

    def test_classify_without_model(self):
        """Test classification without loaded model (rule-based)"""
        async def test():
            result = await self.classifier.classify(
                subject="Team meeting",
                body="Hi team, meeting at 2 PM",
                sender="manager@company.com"
            )

            self.assertIsInstance(result, dict)
            self.assertIn('classification', result)
            self.assertIn('confidence', result)
            self.assertIn('risk_level', result)
            self.assertIn('method', result)
            self.assertEqual(result['method'], 'rule-based')

        asyncio.run(test())

    def test_warnings_generation(self):
        """Test warning generation"""
        warnings = self.classifier._generate_warnings(
            features={
                'sender_brand_impersonation': 1,
                'subject_has_urgency': 1,
                'phishing_keyword_count': 5,
                'suspicious_url_count': 1,
                'ip_url_count': 1,
                'reply_to_mismatch': 1,
                'subject_all_caps_ratio': 0.6
            },
            classification=EmailClassifier.PHISHING
        )

        self.assertIsInstance(warnings, list)
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any('brand name' in w.lower() for w in warnings))
        self.assertTrue(any('urgent' in w.lower() for w in warnings))


class TestEmailClassifierIntegration(unittest.TestCase):
    """Integration tests for email classifier"""

    def test_full_classification_pipeline(self):
        """Test full classification pipeline"""
        async def test():
            classifier = EmailClassifier()

            test_emails = [
                {
                    "subject": "Team meeting tomorrow",
                    "body": "Hi everyone, meeting at 2 PM in room A",
                    "sender": "manager@company.com",
                    "expected": EmailClassifier.LEGITIMATE
                },
                {
                    "subject": "URGENT: Verify your account NOW!",
                    "body": "Click here to verify: http://192.168.1.1/verify",
                    "sender": "security@paypa1.com",
                    "expected": EmailClassifier.PHISHING
                },
                {
                    "subject": "YOU'VE WON $1,000,000!!!",
                    "body": "Claim your prize now! Free money guaranteed!",
                    "sender": "lottery@winner.com",
                    "expected": EmailClassifier.SPAM
                }
            ]

            for email in test_emails:
                result = await classifier.classify(
                    email["subject"],
                    email["body"],
                    email["sender"]
                )

                # Verify result structure
                self.assertIn('classification', result)
                self.assertIn('confidence', result)
                self.assertIn('risk_level', result)
                self.assertIn('features', result)
                self.assertIn('warnings', result)

                # Verify classification matches expected (for rule-based)
                # Note: ML classification may differ
                if result['method'] == 'rule-based':
                    self.assertEqual(result['classification'], email['expected'],
                                   f"Failed for: {email['subject']}")

        asyncio.run(test())


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestEmailClassifier))
    suite.addTests(loader.loadTestsFromTestCase(TestEmailClassifierIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
