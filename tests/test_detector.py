import json

from universal_dev_security.detector import detect_project


def test_detects_python_project(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    result = detect_project(tmp_path)
    assert "python" in result["detected"]
    assert result["network_used"] is False
    assert result["dependency_manifests"] is True


def test_detects_generic_project(tmp_path):
    result = detect_project(tmp_path)
    assert result["detected"] == ["generic"]
    assert result["recommended_scanners"] == ["gitleaks"]


def test_detects_dotnet_by_extension_regression(tmp_path):
    # Regression: 0.4.1 compared ".csproj" against whole file names and never matched.
    (tmp_path / "App.csproj").write_text("<Project />", encoding="utf-8")
    (tmp_path / "App.sln").write_text("", encoding="utf-8")
    assert "dotnet" in detect_project(tmp_path)["detected"]


def test_detects_react_nextjs_typescript(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"next": "15.0.0", "react": "19.0.0"}, "devDependencies": {"typescript": "5.6.0"},
    }), encoding="utf-8")
    detected = detect_project(tmp_path)["detected"]
    for tech in ("node", "javascript", "typescript", "react", "nextjs"):
        assert tech in detected


def test_detects_wordpress_and_woocommerce(tmp_path):
    plugin = tmp_path / "wp-content" / "plugins" / "woocommerce"
    plugin.mkdir(parents=True)
    (plugin / "woocommerce.php").write_text("<?php\n", encoding="utf-8")
    (tmp_path / "wp-config.php").write_text("<?php\n", encoding="utf-8")
    detected = detect_project(tmp_path)["detected"]
    assert {"php", "wordpress", "woocommerce"} <= set(detected)


def test_detects_docker_java_and_nested_projects(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    (tmp_path / "service").mkdir()
    (tmp_path / "service" / "pom.xml").write_text("<project/>", encoding="utf-8")
    result = detect_project(tmp_path)
    assert {"docker", "java"} <= set(result["detected"])
    assert result["infrastructure_as_code"] is True
    assert "trivy" in result["recommended_scanners"]


def test_ignores_node_modules_and_venv(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text("{}", encoding="utf-8")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "x.py").write_text("", encoding="utf-8")
    assert detect_project(tmp_path)["detected"] == ["generic"]


def test_malformed_package_json_does_not_crash(tmp_path):
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    assert "node" in detect_project(tmp_path)["detected"]
