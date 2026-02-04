"""
Test script to verify that model metrics are being sent correctly from the API.
"""
import requests
import json

# Test the API endpoint
url = "http://localhost:5000/check_url"
test_data = {"url": "https://example.com"}

try:
    response = requests.post(url, json=test_data, timeout=5)
    if response.status_code == 200:
        data = response.json()
        print("API Response:")
        print(f"Model Name: {data.get('modelName')}")
        print(f"\nActive Model Metrics:")
        active_metrics = data.get('modelMetrics', {})
        print(f"  Accuracy: {active_metrics.get('accuracy', 0):.4f} ({active_metrics.get('accuracy', 0)*100:.1f}%)")
        print(f"  Recall: {active_metrics.get('recall_phishing', 0):.4f} ({active_metrics.get('recall_phishing', 0)*100:.1f}%)")
        print(f"  F1: {active_metrics.get('f1_phishing', 0):.4f} ({active_metrics.get('f1_phishing', 0)*100:.1f}%)")
        
        print(f"\nModel Comparisons:")
        comparisons = data.get('modelComparisons', {})
        for model_name, metrics in comparisons.items():
            print(f"\n{model_name}:")
            print(f"  Accuracy: {metrics.get('accuracy', 0):.4f} ({metrics.get('accuracy', 0)*100:.1f}%)")
            print(f"  Recall: {metrics.get('recall_phishing', 0):.4f} ({metrics.get('recall_phishing', 0)*100:.1f}%)")
            print(f"  F1: {metrics.get('f1_phishing', 0):.4f} ({metrics.get('f1_phishing', 0)*100:.1f}%)")
        
        # Check if all metrics are the same
        if comparisons:
            first_metrics = list(comparisons.values())[0]
            all_same = all(
                m.get('accuracy') == first_metrics.get('accuracy') and
                m.get('recall_phishing') == first_metrics.get('recall_phishing') and
                m.get('f1_phishing') == first_metrics.get('f1_phishing')
                for m in comparisons.values()
            )
            if all_same:
                print("\n⚠️  WARNING: All models have the same metrics!")
            else:
                print("\n✓ All models have different metrics as expected.")
    else:
        print(f"Error: API returned status code {response.status_code}")
        print(response.text)
except requests.exceptions.ConnectionError:
    print("Error: Could not connect to the Flask server.")
    print("Make sure the Flask server is running on http://localhost:5000")
except Exception as e:
    print(f"Error: {e}")

