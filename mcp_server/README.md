# MCP-Based Email Classification System

This document describes the MCP (Model Context Protocol) based email classification system for detecting phishing, spam, malicious, and legitimate emails.

## Overview

The email classification system uses machine learning and rule-based techniques to analyze emails and classify them into four categories:

- **Legitimate**: Normal, safe emails
- **Spam**: Unsolicited bulk emails, promotional content
- **Phishing**: Emails attempting to steal credentials or sensitive information
- **Malicious**: Emails containing malware, ransomware, or other threats

## Architecture

The system consists of several components:

1. **MCP Server** (`mcp_server/email_classifier_server.py`): JSON-RPC server implementing the Model Context Protocol
2. **Email Classifier** (`mcp_server/email_classifier.py`): Core classification logic with feature extraction
3. **Training Script** (`mcp_server/train_email_model.py`): Model training pipeline
4. **CLI Tool** (`mcp_server/classify_email_cli.py`): Command-line interface for quick classification
5. **Client Example** (`mcp_server/client_example.py`): Example MCP client implementation
6. **Tests** (`tests/test_email_classifier.py`): Comprehensive test suite

## Installation

### Prerequisites

Install the required dependencies:

```bash
pip install -r requirements.txt
```

The system uses the same dependencies as the URL phishing detection system, plus async support.

### Directory Structure

```
Fortnox/
├── mcp_server/
│   ├── __init__.py
│   ├── email_classifier_server.py   # MCP server
│   ├── email_classifier.py          # Classifier logic
│   ├── train_email_model.py         # Training script
│   ├── classify_email_cli.py        # CLI tool
│   └── client_example.py            # Example client
├── models/
│   └── email_classifier_model.joblib  # Trained model (generated)
├── data/
│   └── email_dataset.csv             # Training dataset (optional)
└── tests/
    └── test_email_classifier.py      # Test suite
```

## Quick Start

### 1. Train the Model (Optional)

The system works with rule-based classification out of the box. For better accuracy, train a machine learning model:

```bash
cd mcp_server
python train_email_model.py
```

This will:
- Create a sample dataset if no dataset exists
- Train multiple models (Logistic Regression, Random Forest, XGBoost)
- Select the best model based on accuracy
- Save the model to `models/email_classifier_model.joblib`

### 2. Use the CLI Tool

Classify a single email:

```bash
cd mcp_server
python classify_email_cli.py \
    --subject "Team meeting tomorrow" \
    --body "Hi team, we have a meeting at 2 PM in room A" \
    --sender "manager@company.com"
```

### 3. Use the MCP Server

Start the MCP server:

```bash
cd mcp_server
python email_classifier_server.py
```

The server communicates via stdin/stdout using JSON-RPC protocol.

### 4. Use the Example Client

Run the example client to see the MCP server in action:

```bash
cd mcp_server
python client_example.py
```

This will:
- Start the MCP server
- Classify several example emails
- Demonstrate batch classification
- Display detailed results

## MCP Protocol

### Available Tools

The MCP server exposes two tools:

#### 1. `classify_email`

Classifies a single email.

**Input:**
```json
{
  "subject": "Email subject",
  "body": "Email body content",
  "sender": "sender@example.com",
  "headers": {  // Optional
    "Reply-To": "reply@example.com"
  },
  "links": [  // Optional
    "http://example.com/link1"
  ]
}
```

**Output:**
```json
{
  "classification": "phishing",
  "confidence": 0.89,
  "risk_level": "High",
  "risk_scores": {
    "phishing": 0.89,
    "spam": 0.23,
    "malicious": 0.15
  },
  "warnings": [
    "Sender address contains a brand name - possible impersonation",
    "Subject contains urgent language"
  ],
  "method": "rule-based"
}
```

#### 2. `analyze_email_batch`

Classifies multiple emails in batch.

**Input:**
```json
{
  "emails": [
    {
      "subject": "Email 1 subject",
      "body": "Email 1 body",
      "sender": "sender1@example.com"
    },
    {
      "subject": "Email 2 subject",
      "body": "Email 2 body",
      "sender": "sender2@example.com"
    }
  ]
}
```

**Output:**
```json
{
  "count": 2,
  "results": [
    { /* classification result 1 */ },
    { /* classification result 2 */ }
  ]
}
```

## Feature Extraction

The classifier extracts 30+ features from each email:

### Subject Features
- Length, urgency indicators, reward indicators
- Security-related keywords
- All-caps ratio, punctuation counts

### Sender Features
- Length, presence of numbers
- Suspicious TLDs (.tk, .ml, .ga, etc.)
- Common provider detection
- Brand impersonation detection

### Body Features
- Length, word count
- Phishing keyword count
- Spam keyword count
- Malicious keyword count

### URL/Link Features
- Link count
- Suspicious URL count (IP addresses, URL shorteners, suspicious TLDs)

### Text Analysis
- Special character count
- Number count
- Uppercase ratio
- Shannon entropy

### Header Features
- Reply-To presence
- Reply-To mismatch with sender

## Classification Methods

### Rule-Based Classification

When no trained model is available, the system uses rule-based classification:

1. Calculate risk scores for each category based on feature weights
2. Select the category with the highest score
3. Determine confidence based on score magnitude
4. Generate warnings based on detected features

### Machine Learning Classification

When a trained model is available:

1. Extract and scale numerical features
2. Vectorize text using TF-IDF
3. Combine features and feed to classifier
4. Get probabilities for each class
5. Select class with highest probability

## Training Your Own Model

### Prepare Your Dataset

Create a CSV file with the following columns:
- `subject`: Email subject line
- `body`: Email body content
- `sender`: Sender email address
- `label`: Classification (legitimate, spam, phishing, malicious)

Example:
```csv
subject,body,sender,label
"Meeting tomorrow","Hi team, meeting at 2 PM",manager@company.com,legitimate
"URGENT: Verify account","Click here to verify",security@paypa1.com,phishing
```

Save to `data/email_dataset.csv`

### Train the Model

```bash
cd mcp_server
python train_email_model.py
```

The script will:
1. Load your dataset (or create a sample one)
2. Extract features from emails
3. Train multiple models
4. Compare performance
5. Save the best model

### Model Performance

The training script outputs:
- Accuracy, precision, recall, F1 score for each model
- Confusion matrix
- Classification report
- Model comparison

## Integration Examples

### Python Integration

```python
import asyncio
from email_classifier import EmailClassifier

async def classify():
    classifier = EmailClassifier()
    await classifier.load_model()

    result = await classifier.classify(
        subject="URGENT: Verify your account",
        body="Click here to verify your identity",
        sender="security@paypal-verify.com",
        links=["http://192.168.1.1/verify"]
    )

    print(f"Classification: {result['classification']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Risk Level: {result['risk_level']}")

asyncio.run(classify())
```

### MCP Client Integration

```python
from client_example import EmailClassifierMCPClient

client = EmailClassifierMCPClient('email_classifier_server.py')
client.start_server()

result = client.classify_email(
    subject="Team meeting",
    body="Meeting at 2 PM",
    sender="manager@company.com"
)

print(result)

client.stop_server()
```

## Testing

Run the test suite:

```bash
cd tests
python test_email_classifier.py
```

Tests cover:
- Feature extraction for all email types
- Rule-based classification
- Warning generation
- Full classification pipeline
- Integration tests

## API Reference

### EmailClassifier

Main classifier class.

**Methods:**

- `__init__(model_path: str = None)`: Initialize classifier
- `async load_model()`: Load trained model
- `extract_email_features(subject, body, sender, headers, links)`: Extract features
- `async classify(subject, body, sender, headers, links)`: Classify email

### EmailClassifierMCPServer

MCP server implementing JSON-RPC protocol.

**Methods:**

- `__init__()`: Initialize server
- `async initialize()`: Load model
- `async handle_request(request)`: Handle JSON-RPC request
- `async run()`: Run server loop

## Configuration

### Environment Variables

- `MODEL_PATH`: Path to trained model file (default: `../models/email_classifier_model.joblib`)

### Model Configuration

Edit `train_email_model.py` to configure:
- Model algorithms
- Feature extraction parameters
- Training/test split ratio
- TF-IDF parameters

## Troubleshooting

### Model Not Found

If you see "Model file not found" warnings:
1. Run `python train_email_model.py` to train a model
2. Or use rule-based classification (automatic fallback)

### Poor Classification Accuracy

If rule-based classification isn't accurate enough:
1. Train a model with your own dataset
2. Increase dataset size (more examples = better accuracy)
3. Add more features in `extract_email_features()`

### Server Connection Issues

If the MCP server fails to start:
1. Check Python version (3.7+ required)
2. Verify all dependencies are installed
3. Check for port conflicts
4. Review server logs for errors

## Performance

### Rule-Based Classification
- **Speed**: ~1ms per email
- **Accuracy**: 60-75% (depends on email characteristics)
- **No training required**

### ML-Based Classification
- **Speed**: ~5-10ms per email
- **Accuracy**: 85-95% (with good training data)
- **Requires training**

### Batch Processing
- Efficiently processes multiple emails
- Recommended for bulk classification

## Security Considerations

1. **Input Validation**: All inputs are validated before processing
2. **Sandboxed Execution**: No code execution from email content
3. **URL Analysis**: URLs are analyzed but not visited
4. **Privacy**: No data is sent to external servers
5. **Local Processing**: All classification happens locally

## Future Enhancements

Potential improvements:

1. **Deep Learning**: Use neural networks for better accuracy
2. **Attachment Analysis**: Scan attachments for malware
3. **Sender Reputation**: Track sender history
4. **Real-time Updates**: Continuously update model with new threats
5. **Multi-language Support**: Support non-English emails
6. **Image Analysis**: Analyze images in HTML emails
7. **Header Analysis**: Deep dive into email headers
8. **Integration with Email Clients**: Plugins for Outlook, Gmail, etc.

## Contributing

To contribute:

1. Add features in `email_classifier.py`
2. Update training script if needed
3. Add tests in `test_email_classifier.py`
4. Update this documentation
5. Submit a pull request

## License

Same license as the main Fortnox project.

## Support

For issues or questions:
- Check this documentation
- Review example code
- Check test cases for usage examples
- Open an issue on GitHub

## Comparison with URL Classification

This email classification system is inspired by the existing URL phishing detection system in Fortnox:

| Feature | URL Classification | Email Classification |
|---------|-------------------|---------------------|
| Input | URLs | Emails (subject, body, sender) |
| Categories | Safe/Phishing (2) | Legitimate/Spam/Phishing/Malicious (4) |
| Feature Count | 28 | 30+ |
| Protocol | HTTP API (Flask) | MCP (JSON-RPC) |
| Integration | Chrome Extension | MCP Clients |
| Training Data | URL dataset | Email dataset |

Both systems share:
- Feature extraction patterns
- ML model training pipeline
- TF-IDF vectorization
- Multiple model support
- Rule-based fallback
- Comprehensive testing

## Acknowledgments

Built using techniques from:
- Fortnox URL phishing detection system
- Model Context Protocol (MCP) specification
- Scikit-learn machine learning library
- Industry best practices in email security
