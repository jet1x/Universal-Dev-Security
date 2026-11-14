from universal_dev_security.initializer import initialize_project


def test_init_creates_config_without_secrets(tmp_path):
    result = initialize_project(tmp_path)
    assert result["status"] == "initialized"
    config = (tmp_path / ".uds" / "config.toml").read_text(encoding="utf-8")
    assert "require_user_approval_for_git_push = true" in config
    assert "API_KEY=" not in config


def test_init_does_not_overwrite_existing_file(tmp_path):
    uds = tmp_path / ".uds"
    uds.mkdir()
    config = uds / "config.toml"
    config.write_text("user-owned = true\n", encoding="utf-8")
    result = initialize_project(tmp_path)
    assert result["status"] == "already_initialized"
    assert config.read_text(encoding="utf-8") == "user-owned = true\n"
