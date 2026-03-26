# Comparison: Traditional ML vs LLM-Based Email Classification

## Quick Decision Guide

**Use LLM-Based (Recommended) if:**
- ✅ You want the best accuracy (95-99%)
- ✅ You need AI reasoning and explanations
- ✅ You want to handle new attack types automatically
- ✅ You need multi-language support
- ✅ Budget allows ~$5 per 1000 emails
- ✅ You can use external APIs (Anthropic/OpenAI)

**Use Traditional ML if:**
- ✅ You need 100% offline/local processing
- ✅ Zero API costs are required
- ✅ You have existing training data
- ✅ 85-95% accuracy is acceptable
- ✅ External API calls are not allowed

## Detailed Comparison

### Architecture

**Traditional ML:**
```
Email → Feature Extraction → Scaler → Vectorizer → scikit-learn Model → Classification
         (30+ features)        (StandardScaler)  (TF-IDF)    (LogReg/RF/XGB)
```

**LLM-Based:**
```
Email → Prompt Creation → LLM API (Claude/GPT) → JSON Response → Classification + Reasoning
         (Natural language)    (AI Analysis)          (Structured)
```

### Technical Details

| Aspect | Traditional ML | LLM-Based |
|--------|---------------|-----------|
| **Classification Method** | Pattern matching | AI reasoning |
| **Model Type** | scikit-learn, XGBoost | Claude, GPT-4 |
| **Training** | Required (joblib model) | Not needed |
| **Features** | 30+ manual features | Natural language |
| **Input Processing** | Feature engineering | Prompt engineering |
| **Output** | Label + probability | Label + reasoning + indicators |
| **Update Frequency** | Must retrain | Always current |
| **Dependencies** | scikit-learn, pandas, numpy | anthropic/openai, python-dotenv |

### Performance

| Metric | Traditional ML | LLM-Based |
|--------|---------------|-----------|
| **Accuracy** | 85-95% | 95-99% |
| **Speed** | ~1ms per email | ~500-1000ms per email |
| **Latency** | Instant (local) | API call delay |
| **Throughput** | Very high | Limited by API rate |
| **Consistency** | Deterministic | Mostly consistent |
| **Explainability** | Limited | Excellent |

### Cost Analysis

**Traditional ML:**
- Setup: Free
- Training: One-time compute cost
- Per-email: $0
- Total for 1M emails: $0

**LLM-Based (Claude/Anthropic):**
- Setup: Free (just API key)
- Training: $0 (no training)
- Per-email: ~$0.005
- Total for 1M emails: ~$5,000

**LLM-Based (OpenAI/GPT):**
- Setup: Free (just API key)
- Training: $0 (no training)
- Per-email: ~$0.011
- Total for 1M emails: ~$11,000

### Example Classifications

#### Example 1: Simple Phishing

**Email:**
```
Subject: URGENT: Verify your account
From: security@paypal-verify.tk
Body: Click here immediately: http://192.168.1.1/verify
```

**Traditional ML Output:**
```json
{
  "classification": "phishing",
  "confidence": 0.876,
  "risk_level": "High",
  "method": "machine-learning"
}
```

**LLM-Based Output:**
```json
{
  "classification": "phishing",
  "confidence": 0.95,
  "risk_level": "High",
  "reasoning": "Classic phishing attempt with urgent language, suspicious TLD (.tk), IP address link, and PayPal impersonation",
  "risk_indicators": [
    "Sender domain 'paypal-verify.tk' mimics PayPal",
    "Uses suspicious .tk TLD",
    "Link uses IP address instead of domain",
    "Creates false urgency",
    "Threatens account action"
  ],
  "recommendations": "Delete immediately. Never click links. Visit paypal.com directly.",
  "method": "llm-based",
  "provider": "anthropic",
  "model": "claude-3-5-sonnet-20241022"
}
```

#### Example 2: Sophisticated Attack

**Email:**
```
Subject: Re: Project deliverables for Q4
From: manager@company.com
Body: Hi, I've reviewed the documents. Please see the attached updated budget spreadsheet.
[Attachment: Q4_Budget_Final.xlsm]
```

**Traditional ML Output:**
```json
{
  "classification": "legitimate",
  "confidence": 0.823,
  "risk_level": "Low",
  "method": "machine-learning"
}
```
❌ **FALSE NEGATIVE** - Misses macro-enabled attachment threat

**LLM-Based Output:**
```json
{
  "classification": "malicious",
  "confidence": 0.87,
  "risk_level": "High",
  "reasoning": "While sender and subject appear legitimate, the .xlsm extension indicates a macro-enabled Excel file, commonly used for malware delivery. Generic greeting without specific project details is suspicious.",
  "risk_indicators": [
    "Macro-enabled Excel file (.xlsm) - can execute code",
    "Generic greeting without personalization",
    "Unexpected attachment in thread context",
    "File name suggests finality ('Final') creating urgency"
  ],
  "recommendations": "Verify with sender via separate channel before opening. Scan attachment with antivirus. Consider requesting PDF version instead.",
  "method": "llm-based",
  "provider": "anthropic"
}
```
✅ **CORRECT** - Identifies sophisticated threat

### When Traditional ML Fails

1. **New Attack Patterns**: Can't recognize attacks it wasn't trained on
2. **Sophisticated Social Engineering**: Misses context and psychology
3. **Multi-stage Attacks**: Doesn't understand campaign context
4. **Cultural/Language Nuances**: Limited to training data patterns
5. **Legitimate-Looking Threats**: Can't reason about intent

### When LLM Excels

1. **Context Understanding**: Grasps full email context
2. **Intent Recognition**: Understands malicious intent
3. **Novel Threats**: Recognizes new attack patterns
4. **Reasoning**: Explains why something is suspicious
5. **Nuanced Analysis**: Catches sophisticated attacks

### Security Considerations

**Traditional ML:**
- ✅ All processing is local
- ✅ No data leaves your infrastructure
- ✅ No external dependencies
- ❌ Must handle PII carefully in training data

**LLM-Based:**
- ❌ Email content sent to third-party API
- ❌ Dependent on external service availability
- ✅ Anthropic/OpenAI have strong privacy policies
- ⚠️  Consider PII implications before using

### Scalability

**Traditional ML:**
- Can process thousands of emails per second
- Limited only by server resources
- Easy to horizontally scale
- Perfect for batch processing

**LLM-Based:**
- Limited by API rate limits (~50-100 req/sec)
- Higher latency per email
- Requires rate limiting logic
- Better for real-time analysis of smaller volumes

### Hybrid Approach (Recommended for Enterprise)

Best of both worlds:

```python
async def hybrid_classify(email):
    # Quick ML screening
    ml_result = ml_classifier.classify(email)

    # If uncertain or high-risk, use LLM
    if ml_result['confidence'] < 0.8 or ml_result['classification'] != 'legitimate':
        llm_result = await llm_classifier.classify(email)
        return llm_result

    return ml_result
```

This approach:
- Uses free ML for obvious cases (80%+ of emails)
- Uses LLM for uncertain/suspicious cases (20% of emails)
- Reduces cost by 80% while maintaining LLM quality
- Provides reasoning when it matters most

## Recommendations by Use Case

### Personal Use (< 100 emails/day)
→ **LLM-Based** - Cost is negligible, best protection

### Small Business (100-1000 emails/day)
→ **LLM-Based** - ~$1.50-$15/day for superior security

### Medium Business (1000-10000 emails/day)
→ **Hybrid** - ML screening + LLM for suspicious emails

### Enterprise (10000+ emails/day)
→ **Traditional ML with LLM spot-checking**
  - Use ML for bulk processing
  - LLM for user-reported suspicious emails
  - LLM for training data generation

### Regulated Industries (Healthcare, Finance)
→ **Traditional ML** - Keep all data on-premises

### Security Research
→ **LLM-Based** - Need reasoning and adaptability

## Migration Path

If you're currently using Traditional ML:

1. **Phase 1**: Run both in parallel, compare results
2. **Phase 2**: Use LLM for discrepancies > X threshold
3. **Phase 3**: Switch fully to LLM or hybrid approach
4. **Phase 4**: Use ML as fallback if API unavailable

## Conclusion

**For most users, LLM-Based is the clear winner:**
- Superior accuracy
- AI reasoning
- Handles new threats
- Worth the minimal cost

**Traditional ML still valuable for:**
- Offline requirements
- Zero-cost constraint
- High-volume batch processing
- Privacy-sensitive environments

Both implementations are available in Fortnox. Choose based on your specific needs.
