from rag_firewall.detectors.output import scan_output


def test_clean_output_passes_through():
    result = scan_output("Paris is the capital of France.")
    assert result.findings == []
    assert result.blocked is False
    assert result.sanitized == "Paris is the capital of France."


def test_openai_key_is_redacted():
    text = "Your key is sk-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
    result = scan_output(text)
    assert "openai_api_key" in result.findings
    assert "sk-AbCd" not in result.sanitized
    assert "[REDACTED:OPENAI_KEY]" in result.sanitized


def test_aws_access_key_is_redacted():
    text = "AKIAIOSFODNN7EXAMPLE is bad to share"
    result = scan_output(text)
    assert "aws_access_key" in result.findings
    assert "[REDACTED:AWS_ACCESS_KEY]" in result.sanitized


def test_private_key_hard_fails():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    result = scan_output(text)
    assert result.blocked is True
    assert "private_key" in result.findings


def test_email_redaction():
    text = "Contact me at john.doe@example.com"
    result = scan_output(text)
    assert "email" in result.findings
    assert "john.doe@example.com" not in result.sanitized


def test_ssn_redaction():
    text = "SSN: 123-45-6789"
    result = scan_output(text)
    assert "us_ssn" in result.findings
    assert "123-45-6789" not in result.sanitized
