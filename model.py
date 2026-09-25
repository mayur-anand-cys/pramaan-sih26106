import os
import re
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin

MODEL_FILE = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")

# Expanded representative dataset for SOC Phishing Detection
DATASET = [
    # --- Phishing Examples (Label = 1) ---
    ("URGENT: Your account has been suspended due to security violations.", 1),
    ("Verify your login details immediately to avoid account termination.", 1),
    ("Action Required: Update billing details and credit card information.", 1),
    ("PayPal: Unauthorized access detected from IP 198.51.100.77. Reset password now.", 1),
    ("Bank Security Alert: Confirm your online banking credentials.", 1),
    ("You have won a $1,000 gift card! Click here to claim your prize.", 1),
    ("Important notice regarding your subscription payment failure.", 1),
    ("Security breach detected! Log in to restore full account access.", 1),
    ("Urgent wire transfer request from CEO. Process immediately.", 1),
    ("Your crypto wallet has been locked. Verify private key to unlock.", 1),
    ("Final Warning: Tax refund waiting for confirmation. Submit details.", 1),
    ("Suspicious activity detected on your Netflix account.", 1),
    ("Update your Apple ID password before account is disabled.", 1),
    ("Urgent document shared via Google Drive. Click link to view.", 1),
    ("Your mailbox is full. Re-verify password to avoid email loss.", 1),
    ("Package delivery failed! Click to update delivery address.", 1),
    ("Direct deposit verification needed for upcoming payroll.", 1),
    ("HR Notice: Updated employee benefits handbook. Login required.", 1),
    ("Security Alert: New device signed into your Microsoft 365.", 1),
    ("Invoice payment overdue! Review attached statement immediately.", 1),
    ("Urgent: Password reset required for corporate VPN access.", 1),
    ("Account Suspension Notification: Click here to verify identity.", 1),
    ("Your Amazon account is restricted. Confirm credit card number.", 1),
    ("Critical security patch required. Download attachment immediately.", 1),
    ("Wire transfer approval needed for vendor payment invoice #9401.", 1),

    # --- Legitimate Examples (Label = 0) ---
    ("Weekly team sync meeting notes and action items for Q3.", 0),
    ("Project status update: Sprint 4 backlog refinement completed.", 0),
    ("Lunch invitation for Friday team building event.", 0),
    ("Quarterly financial report review scheduled for tomorrow at 10 AM.", 0),
    ("Code review request: PR #142 refactoring data pipeline module.", 0),
    ("Happy birthday Sarah! Hope you have a wonderful day.", 0),
    ("Documentation update published for API v2 endpoints.", 0),
    ("Summary of customer feedback from recent user research survey.", 0),
    ("Reminder: Open enrollment for health insurance benefits ends Friday.", 0),
    ("Design mockups ready for review in Figma workspace.", 0),
    ("Engineering all-hands agenda and speaker presentation slides.", 0),
    ("Monthly newsletter: Product updates and upcoming features.", 0),
    ("Release notes for version 1.4.0 rollout to production.", 0),
    ("Notes from discussion on database indexing strategy.", 0),
    ("Thank you for attending the webinar on cloud security best practices.", 0),
    ("System maintenance notification: Planned downtime on Sunday 2 AM.", 0),
    ("Performance review cycle kickoff instructions for managers.", 0),
    ("Welcome to the team! Onboarding checklist for new software engineer.", 0),
    ("Coffee chat invitation to discuss cross-functional collaboration.", 0),
    ("Minutes from yesterday's architecture review board meeting.", 0),
    ("Updated project timeline and delivery roadmap for Q4.", 0),
    ("Feedback requested on draft RFC for authentication microservice.", 0),
    ("Office closure announcement for upcoming national holiday.", 0),
    ("Git commit guidelines and branch naming conventions update.", 0),
    ("Team outing photos uploaded to shared drive folder.", 0)
]

def train_and_save_model(model_path: str = MODEL_FILE) -> Pipeline:
    """Train TF-IDF + LogisticRegression pipeline on built-in dataset and save."""
    texts = [item[0] for item in DATASET]
    labels = [item[1] for item in DATASET]

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ('clf', LogisticRegression(C=1.5, random_state=42))
    ])

    pipeline.fit(texts, labels)
    joblib.dump(pipeline, model_path)
    return pipeline

_MODEL_CACHE = None

def load_or_train_model(model_path: str = MODEL_FILE) -> Pipeline:
    """Load model if exists, otherwise train and return. Caches in memory."""
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    if os.path.exists(model_path):
        try:
            _MODEL_CACHE = joblib.load(model_path)
            return _MODEL_CACHE
        except Exception:
            pass
    _MODEL_CACHE = train_and_save_model(model_path)
    return _MODEL_CACHE

def predict_phishing_probability(text: str, model_path: str = MODEL_FILE) -> float:
    """Return predicted phishing probability (0.0 to 1.0) for given email subject/body text."""
    if not text or not text.strip():
        return 0.0
    
    model = load_or_train_model(model_path)
    probs = model.predict_proba([text])[0]
    # Class index 1 corresponds to Phishing (label 1)
    phishing_prob = float(probs[1])
    return round(phishing_prob, 4)

if __name__ == "__main__":
    m = train_and_save_model()
    print(f"Model trained and saved to {MODEL_FILE}")
    test_text = "URGENT: Verify your account login immediately!"
    prob = predict_phishing_probability(test_text)
    print(f"Test prediction for '{test_text}': {prob * 100:.2f}% phishing probability")
