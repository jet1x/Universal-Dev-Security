"""Conservative, local-only project technology detection and scanning profiles."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from universal_dev_security.projectfiles import ProjectInventory, build_inventory

# Lockfiles and manifests that dependency scanners (OSV-Scanner, Trivy) understand.
DEPENDENCY_FILES = {
    "requirements.txt", "poetry.lock", "pipfile.lock", "pdm.lock", "uv.lock", "pyproject.toml", "setup.py",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "package.json",
    "composer.lock", "composer.json", "gemfile.lock", "cargo.lock", "go.mod", "go.sum",
    "pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts", "packages.lock.json",
    "packages.config", "pubspec.lock", "mix.lock", "conan.lock",
}
DEPENDENCY_SUFFIXES = {".csproj", ".fsproj", ".vbproj"}

CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".java", ".kt", ".cs", ".go", ".rb",
    ".rs", ".scala", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".sh", ".ps1", ".vue", ".svelte",
}

IAC_NAMES = {"dockerfile", "containerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml",
             "compose.yaml", "chart.yaml", "kustomization.yaml"}
IAC_SUFFIXES = {".tf", ".tfvars", ".bicep", ".hcl"}

# Technology profile -> scanners that are meaningful + optional Semgrep rule packs.
# Rule pack names refer to the public Semgrep Registry (https://semgrep.dev/explore).
PROFILES: dict[str, dict[str, Any]] = {
    "generic":     {"scanners": ["gitleaks"], "semgrep": []},
    "python":      {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/python"]},
    "javascript":  {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/javascript"]},
    "typescript":  {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/typescript"]},
    "node":        {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/nodejs"]},
    "react":       {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/react"]},
    "nextjs":      {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/react"]},
    "php":         {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/php"]},
    "wordpress":   {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/php"]},
    "woocommerce": {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/php"]},
    "java":        {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/java"]},
    "dotnet":      {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/csharp"]},
    "go":          {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/golang"]},
    "rust":        {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": []},
    "ruby":        {"scanners": ["gitleaks", "semgrep", "osv-scanner", "trivy"], "semgrep": ["p/ruby"]},
    "docker":      {"scanners": ["gitleaks", "semgrep", "trivy"], "semgrep": ["p/dockerfile"]},
    "terraform":   {"scanners": ["gitleaks", "semgrep", "trivy"], "semgrep": ["p/terraform"]},
    "kubernetes":  {"scanners": ["gitleaks", "semgrep", "trivy"], "semgrep": ["p/kubernetes"]},
}


def _read_json(path: Path, limit: int = 2_000_000) -> dict[str, Any]:
    try:
        if path.stat().st_size > limit:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, UnicodeDecodeError):
        return {}


def _package_json_dependencies(root: Path, inventory: ProjectInventory) -> set[str]:
    deps: set[str] = set()
    for relative in inventory.find("package.json")[:25]:
        data = _read_json(root / relative)
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                deps.update(str(name).lower() for name in section)
    return deps


def _composer_requirements(root: Path, inventory: ProjectInventory) -> set[str]:
    deps: set[str] = set()
    for relative in inventory.find("composer.json")[:25]:
        data = _read_json(root / relative)
        for key in ("require", "require-dev"):
            section = data.get(key)
            if isinstance(section, dict):
                deps.update(str(name).lower() for name in section)
    return deps


def detect_technologies(root: Path, inventory: ProjectInventory) -> dict[str, list[str]]:
    """Return {technology: [evidence, ...]} from file markers and manifests."""
    found: dict[str, list[str]] = {}

    def add(tech: str, evidence: str) -> None:
        found.setdefault(tech, [])
        if evidence not in found[tech] and len(found[tech]) < 5:
            found[tech].append(evidence)

    for name in ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "setup.cfg", "poetry.lock", "uv.lock"):
        for path in inventory.find(name)[:2]:
            add("python", path)
    if inventory.has_suffix(".py") and "python" not in found:
        add("python", "*.py source files")

    js_deps = _package_json_dependencies(root, inventory)
    for path in inventory.find("package.json")[:2]:
        add("node", path)
        add("javascript", path)
    if inventory.has_suffix(".js", ".jsx", ".mjs", ".cjs"):
        add("javascript", "*.js source files")
    if inventory.find("tsconfig.json") or inventory.has_suffix(".ts", ".tsx") or "typescript" in js_deps:
        add("typescript", (inventory.find("tsconfig.json") or ["*.ts source files"])[0])
    if "react" in js_deps or "react-dom" in js_deps:
        add("react", "package.json dependency: react")
    if "next" in js_deps or any(inventory.find(n) for n in ("next.config.js", "next.config.mjs", "next.config.ts")):
        add("nextjs", "package.json dependency: next" if "next" in js_deps else "next.config.*")
        add("react", "Next.js implies React")

    composer = _composer_requirements(root, inventory)
    for path in inventory.find("composer.json")[:2]:
        add("php", path)
    if inventory.has_suffix(".php"):
        add("php", "*.php source files")
    wp_markers = inventory.find("wp-config.php") + inventory.find("wp-config-sample.php") + inventory.find("wp-load.php")
    if wp_markers or inventory.has_path_part("wp-content") or any("wordpress" in d for d in composer):
        add("wordpress", (wp_markers or ["wp-content/"])[0])
        add("php", "WordPress implies PHP")
    plugin_headers = [p for p in inventory.files if p.lower().endswith("woocommerce.php")]
    if (inventory.has_path_part("wp-content/plugins/woocommerce") or plugin_headers
            or any("woocommerce" in d for d in composer)):
        add("woocommerce", (plugin_headers or ["wp-content/plugins/woocommerce/"])[0])

    for name in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"):
        for path in inventory.find(name)[:2]:
            add("java", path)
    if inventory.has_suffix(".java"):
        add("java", "*.java source files")

    for path in [p for p in inventory.files if p.lower().endswith((".sln", ".csproj", ".fsproj", ".vbproj"))][:3]:
        add("dotnet", path)

    for path in inventory.find("go.mod")[:2]:
        add("go", path)
    for path in inventory.find("Cargo.toml")[:2]:
        add("rust", path)
    for path in inventory.find("Gemfile")[:2]:
        add("ruby", path)

    docker = [p for p in inventory.files if p.rsplit("/", 1)[-1].lower() in IAC_NAMES - {"chart.yaml", "kustomization.yaml"}
              or p.rsplit("/", 1)[-1].lower().startswith("dockerfile")]
    for path in docker[:3]:
        add("docker", path)
    for path in [p for p in inventory.files if p.lower().endswith((".tf", ".tfvars"))][:3]:
        add("terraform", path)
    for path in (inventory.find("Chart.yaml") + inventory.find("kustomization.yaml"))[:3]:
        add("kubernetes", path)
    return found


def has_dependency_manifests(inventory: ProjectInventory) -> bool:
    return any(name.lower() in DEPENDENCY_FILES for name in inventory.names) or inventory.has_suffix(*DEPENDENCY_SUFFIXES)


def has_source_code(inventory: ProjectInventory) -> bool:
    return inventory.has_suffix(*CODE_SUFFIXES)


def has_iac(inventory: ProjectInventory) -> bool:
    names = {n.lower() for n in inventory.names}
    return bool(names & IAC_NAMES) or any(n.startswith("dockerfile") for n in names) or inventory.has_suffix(*IAC_SUFFIXES)


def recommended_semgrep_configs(technologies: list[str]) -> list[str]:
    configs = ["p/default"]
    for tech in technologies:
        for config in PROFILES.get(tech, {}).get("semgrep", []):
            if config not in configs:
                configs.append(config)
    return configs


def detect_project(path: Path, inventory: ProjectInventory | None = None) -> dict[str, Any]:
    target = path.expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError(f"Project path is not an existing directory: {target}")
    inventory = inventory or build_inventory(target)
    technologies = detect_technologies(target, inventory)
    detected = sorted(technologies) or ["generic"]
    scanners: list[str] = []
    for tech in detected:
        for scanner in PROFILES.get(tech, PROFILES["generic"])["scanners"]:
            if scanner not in scanners:
                scanners.append(scanner)
    return {
        "path": str(target),
        "detected": detected,
        "evidence": technologies,
        "recommended_scanners": scanners,
        "semgrep_configs": recommended_semgrep_configs(detected) if "semgrep" in scanners else [],
        "dependency_manifests": has_dependency_manifests(inventory),
        "infrastructure_as_code": has_iac(inventory),
        "files_inventoried": len(inventory.files),
        "inventory_truncated": inventory.truncated,
        "detector": "marker-based",
        "network_used": False,
    }
