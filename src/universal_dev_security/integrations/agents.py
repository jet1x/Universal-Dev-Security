"""Generic AI-agent integration interface (`uds guard`).

Any coding agent can ask UDS for a decision before acting by piping a JSON
object to ``uds guard`` (see docs/integrations.md)::

    {"action": "shell", "command": "git push origin main", "project_root": "/repo"}
    {"action": "write_file", "path": "src/app.py", "content": "...", "project_root": "/repo"}

Response (stdout)::

    {"decision": "allow"|"ask"|"deny", "risk": "...", "reason": "...", "matches": [...]}

Exit codes: 0 allow, 1 ask (obtain explicit user approval), 2 deny, 3 invalid request.
Agents must treat any non-zero exit or unparsable output as "do not proceed".
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from universal_dev_security.config import ConfigError, load_config
from universal_dev_security.policy import Action, PolicyEngine

EXIT_CODES = {"allow": 0, "ask": 1, "deny": 2}
MAX_REQUEST_BYTES = 5 * 1024 * 1024


def guard(request_text: str, default_root: str) -> tuple[int, dict[str, Any]]:
    if len(request_text.encode("utf-8", errors="replace")) > MAX_REQUEST_BYTES:
        return 3, {"decision": "deny", "reason": "Request too large."}
    try:
        data = json.loads(request_text)
        if isinstance(data, dict) and not data.get("project_root"):
            data["project_root"] = default_root
        action = Action.from_dict(data)
    except (ValueError, TypeError) as exc:
        return 3, {"decision": "deny", "reason": f"Invalid request: {exc}"}
    try:
        config = load_config(Path(action.project_root))
    except ConfigError:
        return 1, {"decision": "ask", "risk": "high", "reason": "UDS configuration could not be parsed; approval required."}
    decision = PolicyEngine(config).evaluate(action)
    payload = decision.to_dict()
    return EXIT_CODES[decision.decision.value], payload
