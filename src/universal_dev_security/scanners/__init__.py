"""Scanner adapter registry. Adapters are independent and replaceable."""
from __future__ import annotations

from universal_dev_security.scanners.base import ScannerAdapter, ScanOptions
from universal_dev_security.scanners.gitleaks import GitleaksAdapter
from universal_dev_security.scanners.osv import OsvScannerAdapter
from universal_dev_security.scanners.semgrep import SemgrepAdapter
from universal_dev_security.scanners.trivy import TrivyAdapter

_REGISTRY: dict[str, type[ScannerAdapter]] = {
    "gitleaks": GitleaksAdapter,
    "semgrep": SemgrepAdapter,
    "osv-scanner": OsvScannerAdapter,
    "trivy": TrivyAdapter,
}


def available_scanners() -> list[str]:
    return list(_REGISTRY)


def get_scanner(name: str) -> ScannerAdapter:
    try:
        return _REGISTRY[name]()
    except KeyError as exc:
        raise ValueError(f"Unknown scanner: {name}") from exc


def register_scanner(name: str, adapter: type[ScannerAdapter]) -> None:
    """Register a third-party adapter (used by plugins and tests)."""
    if not issubclass(adapter, ScannerAdapter):
        raise TypeError("Adapter must subclass ScannerAdapter")
    _REGISTRY[name] = adapter


__all__ = ["ScannerAdapter", "ScanOptions", "available_scanners", "get_scanner", "register_scanner"]
