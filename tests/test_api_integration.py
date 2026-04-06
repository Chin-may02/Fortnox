import importlib.util
import os
import pathlib
import sys
import unittest
from unittest.mock import patch


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_DIR = PROJECT_ROOT / "app"
APP_FILE = APP_DIR / "app.py"

os.environ.setdefault("MODEL_FILE", "models_during_tests_missing.joblib")
sys.path.insert(0, str(APP_DIR))

spec = importlib.util.spec_from_file_location("fortnox_app_module", APP_FILE)
fortnox_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fortnox_app)


class ApiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.client = fortnox_app.app.test_client()

    def test_check_email_uses_bert_and_preserves_url_analysis(self):
        email_payload = {
            "from_email": "security@paypa1-verify.tk",
            "from_name": "PayPal Security",
            "subject": "URGENT: Verify your account now",
            "body_text": "Click http://paypal-secure-login.tk/verify to avoid suspension.",
            "to_email": "victim@example.com",
        }

        email_model_result = {
            "available": True,
            "model_name": "BERT Email Classifier",
            "risk_score": 0.82,
            "probabilities": [0.18, 0.82],
            "decision_threshold": 0.5,
            "token_count": 54,
            "error": None,
        }

        with patch.object(fortnox_app, "predict_email_with_model", return_value=email_model_result), \
             patch.object(fortnox_app, "model_components", {"model_name": "Linear SVM"}), \
             patch.object(
                 fortnox_app,
                 "predict_single_url",
                 return_value=(1, [0.09, 0.91], ["paypal", "secure"], "Linear SVM", 0.5),
             ):
            response = self.client.post("/check_email", json=email_payload)

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "phishing")
        self.assertGreaterEqual(data["riskScore"], 0.82)
        self.assertEqual(data["modelName"], "BERT Email Classifier")
        self.assertTrue(data["emailModel"]["available"])
        self.assertEqual(data["suspiciousUrlCount"], 1)
        self.assertEqual(len(data["urlAnalysis"]), 1)
        self.assertEqual(data["urlAnalysis"][0]["classification"], "phishing")

    def test_check_email_falls_back_to_heuristics_when_model_unavailable(self):
        email_payload = {
            "from_email": "alerts@fake-bank.xyz",
            "from_name": "Bank Alerts",
            "subject": "Action required",
            "body_text": "Please review the attached file immediately.",
            "to_email": "victim@example.com",
            "attachments": ["account_update.exe"],
        }

        email_model_result = {
            "available": False,
            "model_name": "BERT Email Classifier",
            "risk_score": 0.0,
            "probabilities": [1.0, 0.0],
            "decision_threshold": 0.5,
            "token_count": 0,
            "error": "Model unavailable during test",
        }

        with patch.object(fortnox_app, "predict_email_with_model", return_value=email_model_result), \
             patch.object(fortnox_app, "model_components", {"model_name": "Linear SVM"}), \
             patch.object(
                 fortnox_app,
                 "predict_single_url",
                 return_value=(0, [0.92, 0.08], ["example"], "Linear SVM", 0.5),
             ):
            response = self.client.post("/check_email", json=email_payload)

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["modelName"], "Email Heuristic Fallback")
        self.assertFalse(data["emailModel"]["available"])
        self.assertIn(data["prediction"], {"suspicious", "phishing"})
        self.assertIn("Suspicious attachment detected", data["riskFactors"])

    def test_check_email_uses_html_fallback_for_heuristics(self):
        email_payload = {
            "from_email": "alerts@fake-bank.xyz",
            "from_name": "Bank Alerts",
            "subject": "Security alert",
            "body_text": "",
            "body_html": """
                <div>URGENT: verify your account now.</div>
                <form action="http://fake-bank.xyz/login">
                    <input type="password" name="password" />
                </form>
            """,
            "to_email": "victim@example.com",
        }

        email_model_result = {
            "available": False,
            "model_name": "BERT Email Classifier",
            "risk_score": 0.0,
            "probabilities": [1.0, 0.0],
            "decision_threshold": 0.5,
            "token_count": 0,
            "error": "Model unavailable during test",
        }

        with patch.object(fortnox_app, "predict_email_with_model", return_value=email_model_result), \
             patch.object(fortnox_app, "model_components", {"model_name": "Linear SVM"}), \
             patch.object(
                 fortnox_app,
                 "predict_single_url",
                 return_value=(0, [0.92, 0.08], ["fake", "bank"], "Linear SVM", 0.5),
             ):
            response = self.client.post("/check_email", json=email_payload)

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["modelName"], "Email Heuristic Fallback")
        self.assertGreater(data["emailFeatures"]["body_length"], 0)
        self.assertGreater(data["emailFeatures"]["body_urgency_count"], 0)
        self.assertEqual(data["emailFeatures"]["html_has_form"], 1)
        self.assertEqual(data["emailFeatures"]["html_has_input"], 1)
        self.assertIn("Email contains login form", data["riskFactors"])

    def test_check_url_endpoint_shape_remains_available(self):
        url_model_components = {
            "model_name": "Linear SVM",
            "all_model_metrics": {},
            "best_model_metrics": {},
        }

        with patch.object(fortnox_app, "model_components", url_model_components), \
             patch.object(
                 fortnox_app,
                 "predict_single_url",
                 return_value=(0, [0.88, 0.12], ["example", "com"], "Linear SVM", 0.5),
             ):
            response = self.client.post("/check_url", json={"url": "https://example.com"})

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "safe")
        self.assertEqual(data["modelName"], "Linear SVM")
        self.assertIn("riskScore", data)
        self.assertIn("decisionThreshold", data)


if __name__ == "__main__":
    unittest.main()
