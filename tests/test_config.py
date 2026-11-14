import pytest

from universal_dev_security.config import ConfigError, load_config
from universal_dev_security.initializer import initialize_project


def write_config(tmp_path, text):
    (tmp_path / ".uds").mkdir(exist_ok=True)
    (tmp_path / ".uds" / "config.toml").write_text(text, encoding="utf-8")


def test_missing_config_uses_safe_defaults(tmp_path):
    config = load_config(tmp_path)
    assert config.exists is False
    assert config.require_user_approval_for_git_push is True
    assert config.allow_network is False
    assert "gitleaks" in config.enabled_scanners


def test_default_initialized_config_loads_without_warnings(tmp_path):
    initialize_project(tmp_path)
    config = load_config(tmp_path)
    assert config.exists
    assert config.warnings == []


def test_project_cannot_disable_mandatory_policies(tmp_path):
    write_config(tmp_path, "[policy]\nrequire_user_approval_for_git_push = false\n"
                           "require_user_approval_for_high_risk_changes = false\nallow_commands = ['git push']\n")
    config = load_config(tmp_path)
    assert config.require_user_approval_for_git_push is True
    assert config.require_user_approval_for_high_risk_changes is True
    assert len(config.warnings) == 3


def test_gitleaks_cannot_be_disabled(tmp_path):
    write_config(tmp_path, "[scanners]\nenabled = ['semgrep']\n")
    config = load_config(tmp_path)
    assert config.enabled_scanners == ["gitleaks", "semgrep"]
    assert any("mandatory" in w for w in config.warnings)


def test_invalid_values_fall_back_with_warnings(tmp_path):
    write_config(tmp_path, "[policy]\nfail_on = 'whatever'\nsecurity_mode = 'yolo'\n"
                           "[scanners]\ntimeout_seconds = -5\nenabled = 'gitleaks'\n")
    config = load_config(tmp_path)
    assert config.fail_on == "none"
    assert config.security_mode == "balanced"
    assert config.scanner_timeout_seconds == 600
    assert len(config.warnings) >= 4


def test_malformed_toml_raises_config_error(tmp_path):
    write_config(tmp_path, "[policy\nbroken")
    with pytest.raises(ConfigError):
        load_config(tmp_path)
