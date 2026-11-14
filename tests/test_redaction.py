from universal_dev_security.redaction import REDACTED, find_secrets, redact

from fakes import FAKE_ASSIGNMENT, FAKE_AWS_KEY, FAKE_DB_URL, FAKE_GITHUB_TOKEN, FAKE_HIGH_ENTROPY, FAKE_PRIVATE_KEY_HEADER


def test_detects_known_token_formats_with_line_numbers():
    text = f"line one\naws = '{FAKE_AWS_KEY}'\ntoken: {FAKE_GITHUB_TOKEN}\n{FAKE_PRIVATE_KEY_HEADER}\n"
    found = {(m.rule_id, m.line) for m in find_secrets(text)}
    assert ("aws-access-key-id", 2) in found
    assert ("github-token", 3) in found
    assert ("private-key", 4) in found


def test_generic_assignment_requires_entropy_and_skips_placeholders():
    assert any(m.rule_id == "generic-assigned-secret" for m in find_secrets(FAKE_ASSIGNMENT))
    assert find_secrets("api_key = 'your_api_key_here_please'") == []
    assert find_secrets("password = os.environ['DB_PASSWORD']") == []
    assert find_secrets("password = 'aaaaaaaaaaaaaaaaaaaa'") == []


def test_connection_string_password():
    assert any(m.rule_id == "connection-string-password" for m in find_secrets(FAKE_DB_URL))


def test_redact_removes_values_and_keeps_context():
    text = f"{FAKE_ASSIGNMENT}\nurl={FAKE_DB_URL}\nkey={FAKE_AWS_KEY}"
    result = redact(text)
    for secret in (FAKE_HIGH_ENTROPY, "S3cr3tPassw0rdXyz", FAKE_AWS_KEY):
        assert secret not in result
    assert result.count(REDACTED) == 3
    assert "api_key" in result and "db.internal" in result


def test_clean_text_unchanged():
    text = "def add(a, b):\n    return a + b\n"
    assert find_secrets(text) == []
    assert redact(text) == text
