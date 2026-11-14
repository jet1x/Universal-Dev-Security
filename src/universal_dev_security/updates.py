"""Update checks for UDS and its scanners.

UDS never updates itself or installs scanners. ``check_uds_update`` contacts a
network source only when one is given explicitly, sends nothing but an HTTPS
GET request, and only reports what is available.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

from universal_dev_security import __version__
from universal_dev_security.scanners import available_scanners, get_scanner
from universal_dev_security.scanners.base import parse_version

PYPI_PROJECT = "universal-dev-security"
_REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
MAX_RESPONSE = 2 * 1024 * 1024


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not str(newurl).startswith("https://"):
            raise urllib.error.URLError("Refusing a redirect to a non-HTTPS URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_json(url: str, timeout: int = 15) -> Any:
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS update sources are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": f"uds-update-check/{__version__}",
                                                   "Accept": "application/json"})
    opener = urllib.request.build_opener(_HttpsOnlyRedirects())
    with opener.open(request, timeout=timeout) as response:  # https enforced, including redirects
        return json.loads(response.read(MAX_RESPONSE).decode("utf-8"))


def _version_tuple(text: str) -> tuple[int, ...]:
    """Release-ordering key. Pre-releases (rc/a/b) sort before the final release."""
    parsed = parse_version(text) or (0, 0, 0)
    pre = 0 if re.search(r"\d[.-]?(?:rc|a|b|alpha|beta|dev)\d*$", text.strip().lower()) else 1
    return (*parsed, pre)


def check_uds_update(source: str | None, fetch=_fetch_json) -> dict[str, Any]:
    if not source:
        return {"status": "source_not_configured", "current": __version__,
                "message": "No update source given. Use --source pypi or --source github:OWNER/REPO. "
                           "UDS does not contact the network unless you ask it to."}
    try:
        if source == "pypi":
            data = fetch(f"https://pypi.org/pypi/{PYPI_PROJECT}/json")
            latest = str(data["info"]["version"])
            url = f"https://pypi.org/project/{PYPI_PROJECT}/"
        elif source.startswith("github:"):
            repo = source.split(":", 1)[1]
            if not _REPO_RE.match(repo):
                raise ValueError("Invalid GitHub repository; expected OWNER/REPO")
            data = fetch(f"https://api.github.com/repos/{repo}/releases/latest")
            latest = str(data["tag_name"]).lstrip("v")
            url = str(data.get("html_url") or f"https://github.com/{repo}/releases")
        else:
            raise ValueError("Unknown source; use 'pypi' or 'github:OWNER/REPO'")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": "error", "current": __version__, "message": f"Update check failed: {type(exc).__name__}"}
    except (KeyError, TypeError, ValueError) as exc:
        return {"status": "error", "current": __version__, "message": f"Update check failed: {exc}"}
    newer = _version_tuple(latest) > _version_tuple(__version__)
    return {"status": "update_available" if newer else "up_to_date", "current": __version__, "latest": latest,
            "url": url, "message": ("A newer version is available. Review the changelog, then upgrade with "
                                    "`python -m pip install --upgrade <verified package>` and run `uds doctor`.")
            if newer else "UDS is up to date."}


def scanner_status() -> list[dict[str, Any]]:
    rows = []
    for name in available_scanners():
        info = get_scanner(name).info()
        rows.append({k: info[k] for k in ("name", "installed", "version", "minimum_version", "compatible",
                                          "docs_url", "install_hints")})
    return rows
