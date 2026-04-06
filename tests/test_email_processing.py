import pathlib
import sys
import unittest


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_DIR = PROJECT_ROOT / "app"
sys.path.insert(0, str(APP_DIR))

import email_features  # noqa: E402
import email_model  # noqa: E402


class EmailProcessingTests(unittest.TestCase):
    def test_extract_email_features_uses_html_when_body_text_is_blank(self):
        features = email_features.extract_email_features(
            {
                "from_email": "alerts@bank.xyz",
                "from_name": "Bank Alerts",
                "subject": "Security alert",
                "body_text": "",
                "body_html": """
                    <div>URGENT: verify your account immediately.</div>
                    <a href="http://bank.xyz/login">Sign in</a>
                    <form><input type="password" /></form>
                """,
            }
        )

        self.assertGreater(features["body_length"], 0)
        self.assertGreater(features["body_urgency_count"], 0)
        self.assertEqual(features["html_has_form"], 1)
        self.assertEqual(features["html_has_input"], 1)
        self.assertEqual(features["url_count"], 1)

    def test_build_email_text_uses_html_fallback_and_keeps_context_fields(self):
        combined = email_model.build_email_text(
            {
                "from_name": "Bank Alerts",
                "from_email": "alerts@bank.xyz",
                "reply_to": "security@bank.xyz",
                "to_email": "victim@example.com",
                "subject": "Verify account",
                "body_text": "",
                "body_html": "<div>Please verify your account now.</div>",
                "attachments": ["invoice.zip"],
            },
            extracted_urls=["http://bank.xyz/login"],
        )

        self.assertIn("bank alerts", combined)
        self.assertIn("alerts@bank.xyz", combined)
        self.assertIn("verify account", combined)
        self.assertIn("please verify your account now.", combined)
        self.assertIn("invoice.zip", combined)
        self.assertIn("http://bank.xyz/login", combined)
        self.assertNotIn("<div>", combined)


if __name__ == "__main__":
    unittest.main()
