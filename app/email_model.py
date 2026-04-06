"""
Local BERT email classifier helpers.

This module loads the fine-tuned Hugging Face artifacts saved in
`models/results` and exposes a small inference API for the Flask app.
"""

import os
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional

_IMPORT_ERROR: Optional[Exception] = None

try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
except Exception as exc:  # pragma: no cover - import failure is surfaced at runtime
    torch = None
    AutoModelForSequenceClassification = None
    AutoTokenizer = None
    _IMPORT_ERROR = exc


APP_DIR = os.path.dirname(os.path.abspath(__file__))


def _normalize_whitespace(text: Any) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _strip_html_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html or "")


def _flatten_text(values: Iterable[Any]) -> List[str]:
    flattened: List[str] = []
    for value in values:
        normalized = _normalize_whitespace(value)
        if normalized:
            flattened.append(normalized)
    return flattened


def is_email_model_enabled() -> bool:
    flag = os.environ.get("EMAIL_MODEL_ENABLED", "1").strip().lower()
    return flag not in {"0", "false", "no", "off"}


def get_email_model_path() -> str:
    configured_path = os.environ.get("EMAIL_MODEL_DIR", "../models/results")
    return os.path.normpath(os.path.join(APP_DIR, configured_path))


def get_email_model_max_length() -> int:
    try:
        return max(32, int(os.environ.get("EMAIL_MODEL_MAX_LENGTH", "512")))
    except ValueError:
        return 512


def get_email_model_name() -> str:
    return os.environ.get("EMAIL_MODEL_NAME", "BERT Email Classifier").strip() or "BERT Email Classifier"


def build_email_text(email_data: Dict[str, Any], extracted_urls: Optional[List[str]] = None) -> str:
    """
    Build a single text field that mirrors the notebook's `text_combined` usage.
    """
    body_text = _normalize_whitespace(email_data.get("body_text", ""))
    if not body_text:
        body_text = _normalize_whitespace(_strip_html_tags(email_data.get("body_html", "")))

    urls = extracted_urls if extracted_urls is not None else (email_data.get("urls") or [])
    attachments = email_data.get("attachments") or []

    parts = _flatten_text([
        email_data.get("from_name", ""),
        email_data.get("from_email", ""),
        email_data.get("reply_to", ""),
        email_data.get("to_email", ""),
        email_data.get("subject", ""),
        body_text,
        " ".join(_flatten_text(attachments)),
        " ".join(_flatten_text(urls)),
    ])

    return _normalize_whitespace(" ".join(parts)).lower()


@lru_cache(maxsize=1)
def get_email_model_bundle() -> Dict[str, Any]:
    model_path = get_email_model_path()
    bundle: Dict[str, Any] = {
        "available": False,
        "model_name": get_email_model_name(),
        "model_path": model_path,
        "error": None,
    }

    if not is_email_model_enabled():
        bundle["error"] = "Email model disabled by EMAIL_MODEL_ENABLED."
        return bundle

    if _IMPORT_ERROR is not None:
        bundle["error"] = f"Email model dependencies unavailable: {_IMPORT_ERROR}"
        return bundle

    if not os.path.isdir(model_path):
        bundle["error"] = f"Email model directory not found: {model_path}"
        return bundle

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
        model = AutoModelForSequenceClassification.from_pretrained(model_path, local_files_only=True)
        model.to("cpu")
        model.eval()

        bundle.update({
            "available": True,
            "tokenizer": tokenizer,
            "model": model,
            "model_name": get_email_model_name(),
        })
        return bundle
    except Exception as exc:
        bundle["error"] = f"Failed to load email model from {model_path}: {exc}"
        return bundle


def predict_email_with_model(email_data: Dict[str, Any], extracted_urls: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run local BERT inference on the combined email text.
    """
    combined_text = build_email_text(email_data, extracted_urls)
    bundle = get_email_model_bundle()

    result: Dict[str, Any] = {
        "available": bundle.get("available", False),
        "model_name": bundle.get("model_name", "BERT Email Classifier"),
        "model_path": bundle.get("model_path"),
        "error": bundle.get("error"),
        "input_text": combined_text,
        "prediction": 0,
        "probabilities": [1.0, 0.0],
        "risk_score": 0.0,
        "decision_threshold": 0.5,
        "token_count": 0,
    }

    if not combined_text:
        result["error"] = "Email text is empty after preprocessing."
        return result

    if not bundle.get("available"):
        return result

    tokenizer = bundle["tokenizer"]
    model = bundle["model"]
    max_length = min(get_email_model_max_length(), getattr(tokenizer, "model_max_length", 512))

    encoded = tokenizer(
        combined_text,
        return_tensors="pt",
        truncation=True,
        max_length=max_length,
    )

    result["token_count"] = int(encoded["input_ids"].shape[-1])

    with torch.no_grad():
        logits = model(**encoded).logits
        probabilities = torch.softmax(logits, dim=-1)[0].cpu().tolist()

    safe_prob = float(probabilities[0]) if probabilities else 1.0
    phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else max(0.0, 1.0 - safe_prob)
    prediction = 1 if phishing_prob >= result["decision_threshold"] else 0

    result.update({
        "prediction": prediction,
        "probabilities": [safe_prob, phishing_prob],
        "risk_score": phishing_prob,
    })
    return result
