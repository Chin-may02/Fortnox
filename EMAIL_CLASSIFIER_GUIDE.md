# FORTNOX Email Classifier - User Guide

## Overview

FORTNOX now includes a **real-time email phishing classifier** that works seamlessly in Gmail without requiring any copy-paste operations. The extension automatically analyzes emails as you read them and displays risk indicators directly in the Gmail interface.

## Features

### 🔍 Automatic Email Analysis
- **Real-time scanning**: Automatically analyzes emails when you open them in Gmail
- **No copy-paste needed**: Works seamlessly in the background
- **30+ features analyzed**: Comprehensive analysis of sender, subject, body, URLs, and attachments
- **URL extraction**: Automatically extracts and analyzes all URLs in email body
- **Risk scoring**: Calculates overall phishing risk based on multiple factors

### 🛡️ Comprehensive Detection

The email classifier analyzes:

1. **Sender Information**
   - Sender domain validation (freemail, suspicious TLDs)
   - Brand impersonation detection
   - Reply-to address mismatches
   - Sender authentication (SPF/DKIM when available)

2. **Subject Analysis**
   - Urgency keywords (urgent, verify, suspend, etc.)
   - Financial keywords (money, prize, payment, etc.)
   - Excessive capitalization

3. **Body Content**
   - Text entropy and patterns
   - Urgency and financial keywords
   - Greeting analysis
   - Capitalization ratio

4. **URL Analysis**
   - Extracts all URLs from email body
   - Analyzes each URL using ML models
   - Detects URL shorteners
   - Identifies IP addresses in URLs
   - Checks for suspicious TLDs

5. **Structural Elements**
   - Attachment detection (suspicious file types)
   - HTML forms and input fields (login page detection)
   - HTML/text ratio analysis

### 📊 Risk Levels

- **Low Risk (0-39%)**: Email appears safe
  - Green badge with ✓ icon
  - Auto-hides after 10 seconds

- **Medium Risk (40-69%)**: Suspicious elements detected
  - Yellow badge with ⚡ icon
  - Stays visible for review

- **High Risk (70-100%)**: Strong phishing indicators
  - Red badge with ⚠️ icon
  - Shows warning overlay with risk factors
  - Blocks user interaction until acknowledged

## Installation

### Prerequisites

1. **Flask API Server** must be running:
   ```bash
   cd app
   python app.py
   ```

2. **Trained ML Model** must be available:
   - File: `models/final_phishing_model.joblib`
   - If not present, run: `python training/train_model.py`

### Chrome Extension Setup

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select the `extension` folder from this repository
5. Grant permissions when prompted:
   - Access to mail.google.com
   - Storage and tabs permissions

### Permissions Required

The extension requires the following permissions:
- `*://mail.google.com/*` - To analyze emails in Gmail
- `http://127.0.0.1:5000/*` - To communicate with local Flask API
- `storage` - To save settings and scan history
- `tabs` - To detect active Gmail tabs

## Usage

### Gmail Integration

1. **Open Gmail**: Navigate to [mail.google.com](https://mail.google.com)
2. **Open an email**: Click on any email to read it
3. **Automatic analysis**: The extension automatically extracts and analyzes the email
4. **View results**: A risk badge appears in the top-right corner showing the analysis

### Understanding the Risk Badge

The risk badge displays:
- **Risk percentage**: Overall phishing probability (0-100%)
- **Risk level**: Low/Medium/High classification
- **Risk factors**: List of detected suspicious elements
- **Close button**: Click ×  to dismiss the badge

### Risk Factors

The badge may show various risk factors such as:
- "Suspicious sender domain"
- "Reply-to address mismatch"
- "Brand impersonation attempt"
- "Urgency keywords detected (N)"
- "Financial keywords detected (N)"
- "Suspicious URLs detected (N)"
- "Suspicious attachment detected"
- "Email contains login form"
- "Email authentication failed"

### High-Risk Email Warning

When a high-risk email is detected:
1. A **full-screen warning overlay** appears
2. Shows the detected risk factors
3. Blocks interaction with email content
4. Click "I Understand" to close warning and proceed with caution

### Manual Email Scanning

To manually trigger email analysis:
1. Open the FORTNOX extension popup
2. Click "Scan Current Email" (when on Gmail)
3. View detailed analysis results

## API Endpoints

### Check Email Endpoint

**URL**: `POST http://127.0.0.1:5000/check_email`

**Request Body**:
```json
{
  "from_email": "sender@example.com",
  "from_name": "John Doe",
  "subject": "Verify Your Account",
  "body_text": "Dear user, please verify your account...",
  "body_html": "<html>...</html>",
  "reply_to": "reply@example.com",
  "to_email": "recipient@example.com",
  "attachments": ["invoice.pdf"],
  "headers": {
    "received-spf": "pass",
    "dkim-signature": "..."
  }
}
```

**Required Fields**:
- `from_email` (string): Sender's email address
- `subject` (string): Email subject line
- `body_text` (string): Plain text email body

**Optional Fields**:
- `from_name` (string): Sender's display name
- `to_email` (string): Recipient's email address
- `reply_to` (string): Reply-to address
- `body_html` (string): HTML email body
- `attachments` (array): List of attachment filenames
- `headers` (object): Email headers for authentication analysis
- `urls` (array): Pre-extracted URLs (auto-extracted if not provided)

**Response**:
```json
{
  "prediction": "safe" | "suspicious" | "phishing",
  "riskScore": 0.75,
  "riskLevel": "High Risk",
  "message": "This email shows multiple signs of a phishing attempt.",
  "probabilities": [0.25, 0.75],
  "riskFactors": [
    "Suspicious sender domain",
    "Urgency keywords detected (3)",
    "Suspicious URLs detected (2)"
  ],
  "emailFeatures": {
    "sender_is_freemail": 1,
    "subject_urgency_count": 3,
    "url_count": 5,
    ...
  },
  "urlAnalysis": [
    {
      "url": "http://example-phishing.com",
      "risk": 0.92,
      "classification": "phishing"
    }
  ],
  "suspiciousUrlCount": 2,
  "totalUrls": 5,
  "modelName": "Email Heuristic Classifier",
  "modelMetrics": {
    "type": "rule-based",
    "features_analyzed": 32,
    "urls_analyzed": 5
  }
}
```

## Feature Extraction

The email classifier extracts 32 features from each email:

### Sender Features (8)
- `sender_is_freemail`: Is sender from free email provider
- `sender_has_suspicious_tld`: Suspicious top-level domain
- `sender_domain_length`: Length of sender domain
- `sender_has_numbers`: Numbers in sender email
- `sender_has_hyphen`: Hyphens in sender domain
- `from_name_length`: Length of display name
- `from_name_has_brand`: Brand name in display name
- `reply_to_mismatch`: Reply-to differs from sender

### Subject Features (5)
- `subject_length`: Length of subject line
- `subject_has_re_fwd`: Has Re: or Fwd: prefix
- `subject_urgency_count`: Count of urgency keywords
- `subject_financial_count`: Count of financial keywords
- `subject_caps_ratio`: Ratio of capital letters

### Body Features (5)
- `body_length`: Length of email body
- `body_entropy`: Shannon entropy of body text
- `body_urgency_count`: Urgency keywords in body
- `body_financial_count`: Financial keywords in body
- `has_greeting`: Contains greeting
- `body_caps_ratio`: Capital letter ratio in body

### URL Features (4)
- `url_count`: Number of URLs in email
- `has_ip_in_url`: URLs contain IP addresses
- `has_url_shortener`: Uses URL shortening services
- `suspicious_url_count`: Count of suspicious URLs

### Structural Features (7)
- `has_html`: Email contains HTML
- `attachment_count`: Number of attachments
- `has_suspicious_attachment`: Suspicious file extensions
- `html_to_text_ratio`: HTML to text length ratio
- `html_has_form`: Contains HTML form
- `html_has_input`: Contains input fields
- `has_auth_failure`: Email authentication failure

### Authentication Features (3)
- `has_spf_pass`: SPF check passed
- `has_dkim_pass`: DKIM signature valid
- `has_auth_failure`: Authentication failure detected

## Risk Calculation

The risk score is calculated using a weighted heuristic approach:

1. **Base Risk Factors** (weights):
   - Freemail sender: +0.1
   - Suspicious TLD: +0.15
   - Reply-to mismatch: +0.2
   - Brand impersonation: +0.15
   - Urgency keywords: +0.1-0.2
   - Financial keywords: +0.08-0.15
   - Excessive caps: +0.1
   - Suspicious attachments: +0.25
   - HTML forms: +0.2
   - Auth failure: +0.15

2. **URL Analysis**:
   - Each URL analyzed with ML models
   - Suspicious URL count adds +0.15 per URL (max +0.3)
   - Maximum URL risk incorporated at 70% weight

3. **Final Score**:
   - Sum of all weighted factors
   - Normalized to 0-1 range
   - Mapped to risk levels:
     - 0-0.39: Low Risk
     - 0.4-0.69: Medium Risk
     - 0.7-1.0: High Risk

## Troubleshooting

### Extension Not Working

1. **Check Flask server**:
   ```bash
   # Server should be running on port 5000
   curl http://127.0.0.1:5000/check_url -X POST -H "Content-Type: application/json" -d '{"url":"http://google.com"}'
   ```

2. **Check browser console**:
   - Open Gmail
   - Press F12 (Developer Tools)
   - Look for "[FORTNOX Gmail]" messages in console

3. **Verify permissions**:
   - Go to `chrome://extensions/`
   - Find FORTNOX extension
   - Check that "Site access" includes mail.google.com

### Badge Not Appearing

1. **Refresh Gmail**: Press Ctrl+Shift+R to hard refresh
2. **Reload extension**: Go to `chrome://extensions/` and click reload
3. **Check email content**: Badge only appears for emails with valid sender/subject/body
4. **Browser console**: Check for JavaScript errors

### API Errors

**"Backend fetch error"**: Flask server not running or wrong port
- Solution: Start Flask server: `python app/app.py`

**"No email data provided"**: Email extraction failed
- Solution: Check browser console for extraction errors
- Gmail DOM structure may have changed

**"Missing required fields"**: Incomplete email data
- Solution: Ensure email has sender, subject, and body text

## Advanced Configuration

### Adjust Risk Thresholds

Edit `app/app.py` to customize risk thresholds:

```python
# Line ~401-412 in app.py
if risk_score >= 0.7:  # Change this threshold
    risk_level = "High Risk"
    prediction = "phishing"
elif risk_score >= 0.4:  # Change this threshold
    risk_level = "Medium Risk"
    prediction = "suspicious"
else:
    risk_level = "Low Risk"
    prediction = "safe"
```

### Customize Risk Weights

Edit `app/app.py` to adjust individual risk factor weights:

```python
# Line ~342-396 in app.py
# Example: Increase weight for reply-to mismatch
if email_features.get('reply_to_mismatch', 0) == 1:
    risk_score += 0.3  # Changed from 0.2
    risk_factors.append('Reply-to address mismatch')
```

### Add Custom Keywords

Edit `app/email_features.py` to add custom detection keywords:

```python
# Line ~131-132
urgency_keywords = ['urgent', 'immediate', 'action required', 'verify', 'confirm',
                   'suspend', 'expire', 'locked', 'security alert', 'unusual activity',
                   'your_custom_keyword']  # Add here

# Line ~137-139
financial_keywords = ['money', 'prize', 'winner', 'lottery', 'refund', 'payment',
                     'invoice', 'transfer', 'claim', 'reward', '$', '€', '£',
                     'your_custom_keyword']  # Add here
```

## Integration with Existing Features

### URL Scanning
- Email URLs are automatically analyzed using the same ML models used for web browsing
- Each URL gets individual risk assessment
- Maximum URL risk influences overall email risk score

### Model Switching
- Email classifier uses existing trained models for URL analysis
- Supports all 4 models: Linear SVM, Logistic Regression, Random Forest, XGBoost
- URLs analyzed with active model selected in extension

### Extension Popup
- Shows email analysis results alongside URL scanning
- Displays email feature breakdown
- URL analysis details for each link in email

## Privacy & Security

### Data Handling
- **No data storage**: Emails are analyzed in real-time and not stored
- **Local processing**: All analysis happens locally via Flask API
- **No external requests**: No email data sent to external servers
- **In-memory only**: Email content exists only during analysis

### Permissions
- Extension only accesses Gmail pages (mail.google.com)
- Cannot access email in other tabs or applications
- Cannot modify email content
- Cannot send emails or access account settings

## Future Enhancements

Potential improvements for the email classifier:

1. **ML Model Training**:
   - Train dedicated email phishing ML model
   - Replace heuristic scoring with learned weights
   - Collect labeled email dataset

2. **Outlook Support**:
   - Add content script for Outlook.com
   - Support Office 365 web interface

3. **Advanced Features**:
   - Email header analysis (DMARC, SPF, DKIM parsing)
   - Image analysis (logo detection, OCR)
   - Social engineering detection
   - Contact whitelist/blacklist

4. **UI Enhancements**:
   - Email list view risk badges
   - Detailed analysis popup
   - Historical scan results
   - Export reports

## Support

For issues, feature requests, or contributions:
- GitHub: [Chin-may02/Fortnox](https://github.com/Chin-may02/Fortnox)
- Open an issue with "[Email Classifier]" prefix

## License

Same as parent project (see main README.md)
