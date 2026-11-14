"""Clearly fake credential fixtures, assembled at runtime.

They are split so that secret scanners running over this repository do not
flag the test suite itself. None of these values are real credentials.
"""

FAKE_AWS_KEY = "AKIA" + "Z7FAKEFAKEFAKE12"
FAKE_GITHUB_TOKEN = "ghp" + "_" + "Zx9FakeTokenForUnitTests000000000000a1B2"
FAKE_PRIVATE_KEY_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
FAKE_HIGH_ENTROPY = "q8Zr" + "T2vLx9Wm4KpB7nYs3DfH6jQc"
FAKE_ASSIGNMENT = "api_key = '" + FAKE_HIGH_ENTROPY + "'"
FAKE_DB_URL = "postgres://admin:" + "S3cr3tPassw0rdXyz" + "@db.internal:5432/app"
