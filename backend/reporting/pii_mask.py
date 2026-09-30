"""PII masking utilities for DPDP Act 2023 compliance.

Masks victim email addresses, phone numbers, Aadhaar, and PAN
before they appear in forensic PDF reports. Merkle root still
proves integrity of the original unmasked data.
"""


def mask_pii_email(email_address: str) -> str:
    """'john.doe@company.com' -> 'j***e@company.com'"""
    if not email_address or "@" not in email_address:
        return email_address
    local, domain = email_address.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def mask_pii_phone(phone: str) -> str:
    """'+91-9876543210' -> '+91-98******10'"""
    if not phone:
        return phone
    digits = [c for c in phone if c.isdigit()]
    if len(digits) < 6:
        return phone
    # Keep first 2 and last 2 digits visible
    keep_start = 2
    keep_end = 2
    mask_len = len(digits) - keep_start - keep_end
    masked_digits = "".join(digits[:keep_start]) + "*" * mask_len + "".join(digits[-keep_end:])
    # Rebuild with same prefix/suffix structure (keep '+91-' if present)
    if phone.startswith("+"):
        # Find country code prefix
        prefix = phone[:phone.find(digits[0])]
        return f"{prefix}{masked_digits[:2]}{'*' * mask_len}{masked_digits[-2:]}"
    return masked_digits


def mask_pii_aadhaar(aadhaar: str) -> str:
    """'1234 5678 9012' -> 'XXXX XXXX 9012'"""
    if not aadhaar:
        return aadhaar
    # Keep last 4 digits visible, mask rest
    digits_only = "".join(c for c in aadhaar if c.isdigit())
    if len(digits_only) < 4:
        return aadhaar
    last4 = digits_only[-4:]
    # Reconstruct with same separator pattern
    if " " in aadhaar:
        return f"XXXX XXXX {last4}"
    elif "-" in aadhaar:
        return f"XXXX-XXXX-{last4}"
    return f"XXXXXXXX{last4}"


def mask_pii_pan(pan: str) -> str:
    """'ABCDE1234F' -> 'AB***34F'"""
    if not pan or len(pan) < 6:
        return pan
    # Keep first 2 and last 3 characters visible
    return pan[:2] + "*" * (len(pan) - 5) + pan[-3:]


def mask_text(text: str) -> str:
    """Apply all masking to a free-form string (for headers, bodies)."""
    if not text:
        return text
    import re
    # Email
    text = re.sub(
        r"[\w.+-]+@[\w-]+\.[\w.-]+",
        lambda m: mask_pii_email(m.group(0)),
        text,
    )
    # Phone (Indian format)
    text = re.sub(
        r"\+91[-\s]?\d{10}",
        lambda m: mask_pii_phone(m.group(0)),
        text,
    )
    # Aadhaar (12 digits, may have spaces)
    text = re.sub(
        r"\b\d{4}\s\d{4}\s\d{4}\b",
        lambda m: mask_pii_aadhaar(m.group(0)),
        text,
    )
    # PAN (5 letters + 4 digits + 1 letter)
    text = re.sub(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        lambda m: mask_pii_pan(m.group(0)),
        text,
    )
    return text