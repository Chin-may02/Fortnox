"""
Email Feature Extraction Module for Phishing Detection

This module extracts 30+ features from email content for phishing classification.
Features include header analysis, sender validation, content analysis, and URL extraction.
"""

import re
import numpy as np
from urllib.parse import urlparse
from typing import Dict, List, Any


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    length = len(text)
    entropy = 0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * np.log2(probability)
    return entropy


def strip_html_tags(html: str) -> str:
    """Convert HTML content into a plain-text fallback."""
    if not html:
        return ""
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from email body text."""
    if not text:
        return []

    # Pattern to match HTTP/HTTPS URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)

    # Also look for www. patterns without protocol
    www_pattern = r'www\.[^\s<>"{}|\\^`\[\]]+'
    www_urls = re.findall(www_pattern, text, re.IGNORECASE)
    urls.extend(['http://' + url for url in www_urls])

    return list(set(urls))  # Remove duplicates


def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address."""
    if not email or '@' not in email:
        return ""
    return email.split('@')[-1].lower().strip()


def is_freemail_domain(domain: str) -> bool:
    """Check if domain is a free email provider."""
    freemail_domains = [
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
        'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
        'gmx.com', 'live.com', 'msn.com', 'inbox.com', 'mail.ru'
    ]
    return domain.lower() in freemail_domains


def has_suspicious_tld(domain: str) -> bool:
    """Check if domain has suspicious TLD."""
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top', '.xyz', '.info']
    return any(domain.endswith(tld) for tld in suspicious_tlds)


def extract_email_features(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract comprehensive features from email data for phishing detection.

    Args:
        email_data: Dictionary containing email fields:
            - from_email: Sender email address
            - from_name: Sender display name
            - to_email: Recipient email (optional)
            - subject: Email subject line
            - body_text: Plain text body
            - body_html: HTML body (optional)
            - reply_to: Reply-to address (optional)
            - headers: Dict of email headers (optional)
            - urls: List of URLs in email (optional, will be extracted if not provided)
            - attachments: List of attachment names (optional)

    Returns:
        Dictionary of extracted features
    """
    features = {}

    # Extract fields with defaults
    from_email = email_data.get('from_email', '').strip()
    from_name = email_data.get('from_name', '').strip()
    to_email = email_data.get('to_email', '').strip()
    subject = email_data.get('subject', '').strip()
    body_text = email_data.get('body_text', '').strip()
    body_html = email_data.get('body_html', '')
    if not body_text and body_html:
        body_text = strip_html_tags(body_html)
    reply_to = email_data.get('reply_to', '').strip()
    headers = email_data.get('headers', {})
    attachments = email_data.get('attachments', [])

    # Extract URLs from body if not provided
    urls = email_data.get('urls', [])
    if not urls:
        urls = extract_urls_from_text(body_text)
        if body_html:
            urls.extend(extract_urls_from_text(body_html))
        urls = list(set(urls))

    # === SENDER FEATURES ===
    from_domain = extract_domain_from_email(from_email)
    features['sender_is_freemail'] = int(is_freemail_domain(from_domain))
    features['sender_has_suspicious_tld'] = int(has_suspicious_tld(from_domain))
    features['sender_domain_length'] = len(from_domain)
    features['sender_has_numbers'] = int(bool(re.search(r'\d', from_email)))
    features['sender_has_hyphen'] = int('-' in from_domain)
    features['from_name_length'] = len(from_name)

    # Check if display name mimics a known brand
    brand_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
                     'bank', 'visa', 'mastercard', 'ebay', 'netflix', 'adobe',
                     'dropbox', 'linkedin', 'twitter', 'instagram']
    features['from_name_has_brand'] = int(any(brand in from_name.lower() for brand in brand_keywords))

    # Reply-to mismatch
    reply_to_domain = extract_domain_from_email(reply_to) if reply_to else from_domain
    features['reply_to_mismatch'] = int(reply_to_domain != from_domain and reply_to != '')

    # === SUBJECT FEATURES ===
    features['subject_length'] = len(subject)
    features['subject_has_re_fwd'] = int(any(prefix in subject.lower() for prefix in ['re:', 'fwd:', 'fw:']))

    # Urgency and phishing keywords in subject
    urgency_keywords = ['urgent', 'immediate', 'action required', 'verify', 'confirm',
                       'suspend', 'expire', 'locked', 'security alert', 'unusual activity']
    features['subject_urgency_count'] = sum(1 for word in urgency_keywords if word in subject.lower())

    # Financial/reward keywords
    financial_keywords = ['money', 'prize', 'winner', 'lottery', 'refund', 'payment',
                         'invoice', 'transfer', 'claim', 'reward', '$', '€', '£']
    features['subject_financial_count'] = sum(1 for word in financial_keywords if word in subject.lower())

    # Subject caps ratio
    if len(subject) > 0:
        features['subject_caps_ratio'] = sum(1 for c in subject if c.isupper()) / len(subject)
    else:
        features['subject_caps_ratio'] = 0

    # === BODY CONTENT FEATURES ===
    features['body_length'] = len(body_text)
    features['body_entropy'] = calculate_entropy(body_text)

    # Urgency in body
    features['body_urgency_count'] = sum(1 for word in urgency_keywords if word in body_text.lower())
    features['body_financial_count'] = sum(1 for word in financial_keywords if word in body_text.lower())

    # Suspicious patterns
    features['has_greeting'] = int(any(greeting in body_text.lower() for greeting in ['dear', 'hello', 'hi ', 'greetings']))

    # Body caps ratio
    if len(body_text) > 0:
        features['body_caps_ratio'] = sum(1 for c in body_text if c.isupper()) / len(body_text)
    else:
        features['body_caps_ratio'] = 0

    # === URL FEATURES ===
    features['url_count'] = len(urls)
    features['has_ip_in_url'] = int(any(bool(re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url)) for url in urls))

    # Check for URL shorteners
    shortener_domains = ['bit.ly', 'tinyurl', 'ow.ly', 't.co', 'goo.gl', 'short', 'tiny.cc']
    features['has_url_shortener'] = int(any(any(short in url for short in shortener_domains) for url in urls))

    # Count suspicious URLs (mismatched domains, suspicious TLDs)
    features['suspicious_url_count'] = 0
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if has_suspicious_tld(domain) or re.search(r'\d', domain):
                features['suspicious_url_count'] += 1
        except:
            pass

    # === STRUCTURAL FEATURES ===
    features['has_html'] = int(bool(body_html))
    features['attachment_count'] = len(attachments)

    # Check for suspicious attachment extensions
    if attachments:
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.js', '.vbs', '.zip', '.rar']
        features['has_suspicious_attachment'] = int(any(
            any(att.lower().endswith(ext) for ext in suspicious_extensions)
            for att in attachments
        ))
    else:
        features['has_suspicious_attachment'] = 0

    # HTML-specific features
    if body_html:
        features['html_to_text_ratio'] = len(body_html) / max(len(body_text), 1)
        # Count forms in HTML (phishing often has login forms)
        features['html_has_form'] = int('<form' in body_html.lower())
        features['html_has_input'] = int('<input' in body_html.lower())
    else:
        features['html_to_text_ratio'] = 0
        features['html_has_form'] = 0
        features['html_has_input'] = 0

    # === HEADER FEATURES (if available) ===
    if headers:
        # SPF/DKIM indicators (simplified - real implementation would parse actual results)
        features['has_spf_pass'] = int('pass' in headers.get('received-spf', '').lower())
        features['has_dkim_pass'] = int('pass' in headers.get('dkim-signature', '').lower())

        # Check for authentication results
        auth_results = headers.get('authentication-results', '').lower()
        features['has_auth_failure'] = int('fail' in auth_results or 'none' in auth_results)
    else:
        features['has_spf_pass'] = 0
        features['has_dkim_pass'] = 0
        features['has_auth_failure'] = 0

    # Store extracted URLs for further analysis
    features['extracted_urls'] = urls

    return features


def get_email_feature_columns() -> List[str]:
    """
    Return list of feature column names in order (excluding extracted_urls).
    This ensures consistent feature ordering for ML models.
    """
    return [
        'sender_is_freemail',
        'sender_has_suspicious_tld',
        'sender_domain_length',
        'sender_has_numbers',
        'sender_has_hyphen',
        'from_name_length',
        'from_name_has_brand',
        'reply_to_mismatch',
        'subject_length',
        'subject_has_re_fwd',
        'subject_urgency_count',
        'subject_financial_count',
        'subject_caps_ratio',
        'body_length',
        'body_entropy',
        'body_urgency_count',
        'body_financial_count',
        'has_greeting',
        'body_caps_ratio',
        'url_count',
        'has_ip_in_url',
        'has_url_shortener',
        'suspicious_url_count',
        'has_html',
        'attachment_count',
        'has_suspicious_attachment',
        'html_to_text_ratio',
        'html_has_form',
        'html_has_input',
        'has_spf_pass',
        'has_dkim_pass',
        'has_auth_failure'
    ]
