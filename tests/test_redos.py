"""Regression tests: pattern matching must stay fast on adversarial input (ReDoS).

Found during the 1.0.0rc1 security audit: unbounded quantifiers made the
secret detector take minutes on crafted input, which would freeze the Claude
Code hook. Every input below must be processed well within the budget.
"""
import time

import pytest

from universal_dev_security.policy import Action, ActionKind, Decision, evaluate
from universal_dev_security.redaction import find_secrets, redact

BUDGET_SECONDS = 5.0

CONTENT = {
    "dotted words": "a." * 100_000,
    "jwt prefix repeat": "eyJ" * 66_000,
    "long word": "a" * 500_000,
    "secret-like names": "secret_" * 30_000,
    "url without at-sign": "http://" + "a" * 100_000,
    "assignment soup": "password=" * 20_000,
}

COMMANDS = {
    "git commit repeat": "git commit " * 1800,
    "git push repeat": "git push origin " * 1200,
    "rm repeat": "rm -r " * 3000,
    "curl repeat": "curl x " * 2800,
    "Remove-Item repeat": "Remove-Item " * 1600,
    "many segments": "git status; " * 1600,
}


@pytest.mark.parametrize("name", list(CONTENT))
def test_secret_detection_is_linear(name):
    start = time.perf_counter()
    find_secrets(CONTENT[name])
    redact(CONTENT[name])
    assert time.perf_counter() - start < BUDGET_SECONDS


@pytest.mark.parametrize("name", list(COMMANDS))
def test_policy_evaluation_is_fast(name):
    start = time.perf_counter()
    evaluate(Action(ActionKind.SHELL, command=COMMANDS[name]))
    assert time.perf_counter() - start < BUDGET_SECONDS


def test_oversized_command_requires_approval():
    result = evaluate(Action(ActionKind.SHELL, command="echo " + "a" * 30_000))
    assert result.decision is Decision.ASK
    assert result.matches[0].rule_id == "command-too-long"
