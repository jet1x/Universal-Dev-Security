"""Command-line interface for Universal Dev Security."""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

from universal_dev_security import __version__
from universal_dev_security.config import FAIL_ON_LEVELS, ConfigError, ProjectConfig, load_config
from universal_dev_security.detector import detect_project
from universal_dev_security.initializer import initialize_project

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _out(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _err(message: str) -> None:
    print(f"uds: {message}", file=sys.stderr)


def _project(path: str) -> Path:
    target = Path(path).expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"Not an existing directory: {target}")
    return target


def _config(root: Path) -> ProjectConfig:
    return load_config(root)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_doctor(args: argparse.Namespace) -> int:
    from universal_dev_security.scanners import available_scanners, get_scanner

    root = _project(args.path)
    scanners = [get_scanner(name).info(root) for name in available_scanners()]
    try:
        config = load_config(root)
        config_state = {"exists": config.exists, "warnings": config.warnings}
    except ConfigError as exc:
        config_state = {"exists": True, "error": str(exc)}
    data = {
        "uds_version": __version__,
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()}",
        "git": shutil.which("git") is not None,
        "config": config_state,
        "scanners": scanners,
        "network_used": False,
        "global_settings_modified": False,
    }
    if args.json:
        _out(data)
    else:
        print(f"UDS {__version__} · Python {data['python']} · {data['platform']}")
        print(f"Git available: {'yes' if data['git'] else 'no'}")
        print(f"Project config: {'found' if config_state.get('exists') else 'not initialized'}")
        for warning in config_state.get("warnings", []):
            print(f"  ! {warning}")
        if config_state.get("error"):
            print(f"  ! {config_state['error']}")
        print("Scanners:")
        for s in scanners:
            if not s["installed"]:
                state = "not installed" + (f" ({s['note']})" if s["note"] else "")
            elif not s["compatible"]:
                state = f"installed {s['version'] or 'unknown version'} — UNSUPPORTED (need {s['minimum_version']}+)"
            else:
                state = f"OK {s['version']}"
            print(f"  {s['display_name']:<12} {state}")
            if not s["installed"]:
                hint = s["install_hints"].get({"Windows": "windows", "Darwin": "macos"}.get(platform.system(), "linux"))
                print(f"  {'':<12} install: {hint}  ({s['docs_url']})")
        print("UDS runtime: OK (no network access used, no global settings modified)")
    return EXIT_OK


def cmd_detect(args: argparse.Namespace) -> int:
    _out(detect_project(_project(args.path)))
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    result = initialize_project(Path(args.path))
    _out(result)
    return EXIT_OK if result["status"] in {"initialized", "already_initialized"} else EXIT_ERROR


def cmd_status(args: argparse.Namespace) -> int:
    from universal_dev_security.history import list_scans, load_scan

    target = _project(args.path)
    config = target / ".uds" / "config.toml"
    if not config.is_file():
        print(f"UDS not initialized: {target}")
        print("Run `uds init` to create the local project configuration.")
        return EXIT_FINDINGS
    print(f"UDS initialized: {target}")
    print(f"Configuration: {config}")
    scans = list_scans(target)
    if scans:
        latest = load_scan(target, "latest")
        print(f"Latest scan: {latest['scan_id']} · status {latest['overall_status']} · "
              f"{latest['summary']['finding_count']} finding(s) · scanners run: "
              f"{', '.join(latest['coverage']['executed']) or 'none'}")
    else:
        print("Latest scan: none (run `uds scan`)")
    return EXIT_OK


def _print_scan_summary(scan: dict[str, Any], paths: dict[str, str], comparison: dict[str, Any] | None) -> None:
    summary = scan["summary"]
    print(f"UDS scan {scan['scan_id']} · {scan['target']}")
    print(f"Overall status: {scan['overall_status'].upper()}")
    for s in scan["scanners"]:
        print(f"  {s['tool']:<12} {s['status']:<15} {s['finding_count'] if s['executed'] else '-':>5}  {s['message']}")
    sev = summary["by_severity"]
    print("Findings: " + ", ".join(f"{k} {v}" for k, v in sev.items()) + f" (total {summary['finding_count']})")
    if comparison:
        print(f"Since previous scan: {len(comparison['new'])} new, {len(comparison['resolved'])} resolved, "
              f"{len(comparison['not_rescanned'])} not re-scanned")
        for warning in comparison.get("warnings", []):
            print(f"  ! {warning}")
    for kind, path in paths.items():
        print(f"Report ({kind}): {path}")


def cmd_scan(args: argparse.Namespace) -> int:
    from universal_dev_security.engine import exit_code_for, run_scan
    from universal_dev_security.history import compare_scans, history_summaries, list_scans, load_scan, save_scan
    from universal_dev_security.reports import build_report, write_reports

    root = _project(args.path)
    config = _config(root)
    for warning in config.warnings:
        _err(f"config warning: {warning}")
    progress: Callable[[str], None] | None = None if (args.json or args.quiet) else (lambda m: print(m, file=sys.stderr))
    scan = run_scan(root, config, tools=args.tool or None,
                    allow_network=True if args.allow_network else None, progress=progress)

    comparison = None
    if not args.no_history:
        previous = list_scans(root)
        if previous:
            try:
                comparison = compare_scans(load_scan(root, previous[-1]), scan)
            except (OSError, ValueError):
                comparison = None
        save_scan(root, scan, config.history_limit)
    history = [] if args.no_history else history_summaries(root)
    report = build_report(scan, comparison, history)
    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    paths = write_reports(report, root, Path(args.report_dir) if args.report_dir else None, formats)
    fail_on = args.fail_on or config.fail_on
    code = exit_code_for(scan, fail_on, args.require_complete)
    if args.json:
        _out({"scan_id": scan["scan_id"], "overall_status": scan["overall_status"], "exit_code": code,
              "summary": scan["summary"], "scanners": scan["scanners"], "reports": paths,
              "comparison": {k: (len(v) if isinstance(v, list) else v) for k, v in comparison.items()} if comparison else None})
    elif not args.quiet:
        _print_scan_summary(scan, paths, comparison)
        if code == EXIT_FINDINGS:
            print(f"Result: findings at or above fail-on threshold '{fail_on}'.")
        elif code == EXIT_ERROR:
            print("Result: scan incomplete or failed — results must not be treated as a pass.")
    return code


def cmd_report(args: argparse.Namespace) -> int:
    from universal_dev_security.history import compare_scans, history_summaries, list_scans, load_scan, resolve_scan_id
    from universal_dev_security.reports import build_report, write_reports

    root = _project(args.path)
    scan_id = resolve_scan_id(root, args.scan)
    scan = load_scan(root, scan_id)
    scans = list_scans(root)
    index = scans.index(scan_id)
    comparison = compare_scans(load_scan(root, scans[index - 1]), scan) if index > 0 else None
    history = [h for h in history_summaries(root, 1000) if str(h["scan_id"]) <= scan_id][-20:]
    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    paths = write_reports(build_report(scan, comparison, history), root,
                          Path(args.report_dir) if args.report_dir else None, formats)
    _out(paths)
    return EXIT_OK


def cmd_dashboard(args: argparse.Namespace) -> int:
    root = _project(args.path)
    html = (Path(args.report_dir).expanduser().resolve() if args.report_dir else root / ".uds" / "reports") / "security-report.html"
    if not html.is_file():
        _err("No dashboard found. Run `uds scan` first.")
        return EXIT_ERROR
    print(html)
    if args.open:
        import webbrowser
        webbrowser.open(html.as_uri())
    return EXIT_OK


def cmd_history(args: argparse.Namespace) -> int:
    from universal_dev_security.history import history_summaries

    entries = history_summaries(_project(args.path), args.limit)
    if args.json:
        _out(entries)
        return EXIT_OK
    if not entries:
        print("No scan history. Run `uds scan`.")
        return EXIT_OK
    for e in entries:
        sev = e["by_severity"]
        print(f"{e['scan_id']}  {e['overall_status']:<12} total {e['finding_count']:>4}  "
              + " ".join(f"{k[:4]}:{v}" for k, v in sev.items()) + f"  [{', '.join(e['executed'])}]")
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    from universal_dev_security.history import compare_scans, load_scan

    root = _project(args.path)
    result = compare_scans(load_scan(root, args.base), load_scan(root, args.head))
    if args.json:
        _out(result)
        return EXIT_OK
    print(f"Base {result['base_scan_id']} → head {result['current_scan_id']} (tools: {', '.join(result['compared_tools']) or 'none'})")
    print(f"New: {len(result['new'])}  Resolved: {len(result['resolved'])}  Unchanged: {result['unchanged_count']}  "
          f"Not re-scanned: {len(result['not_rescanned'])}")
    for label in ("new", "resolved"):
        for f in result[label][:50]:
            print(f"  [{label}] {f['severity']:<12} {f['tool']:<11} {f['rule_id']}  {f.get('file') or ''}")
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    from universal_dev_security.policy import GLOBAL_COMMAND_RULES, Action, ActionKind, PolicyEngine

    root = _project(args.path)
    config = _config(root)
    if args.policy_command == "show":
        _out({
            "precedence": ["mandatory global policy", "technology profile", "project configuration"],
            "global_command_rules": [{"rule_id": r.rule_id, "decision": r.decision.value, "risk": r.risk.value,
                                      "reason": r.reason} for r in GLOBAL_COMMAND_RULES],
            "project": config.to_dict(),
        })
        return EXIT_OK
    engine = PolicyEngine(config)
    if args.command_text is not None:
        action = Action(ActionKind.SHELL, command=args.command_text, project_root=str(root))
    else:
        content = Path(args.content_file).read_text(encoding="utf-8", errors="replace") if args.content_file else ""
        action = Action(ActionKind.WRITE_FILE, path=args.write, content=content, project_root=str(root))
    decision = engine.evaluate(action)
    _out(decision.to_dict())
    return {"allow": EXIT_OK, "ask": EXIT_FINDINGS, "deny": EXIT_ERROR}[decision.decision.value]


def cmd_scanners(args: argparse.Namespace) -> int:
    from universal_dev_security.scanners import available_scanners, get_scanner

    _out([get_scanner(name).info(Path.cwd()) for name in available_scanners()])
    return EXIT_OK


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uds", description="Universal Dev Security — One Security System. Every Project.")
    parser.add_argument("--version", action="version", version=f"UDS {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_path(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("path", nargs="?", default=".", help="Project directory (default: current directory)")
        return p

    p = with_path(sub.add_parser("doctor", help="Check the UDS runtime, configuration and scanners"))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_doctor)
    with_path(sub.add_parser("detect", help="Detect project technologies and scanning profile")).set_defaults(func=cmd_detect)
    with_path(sub.add_parser("init", help="Initialize UDS in a project safely (never overwrites)")).set_defaults(func=cmd_init)
    with_path(sub.add_parser("status", help="Show UDS project status")).set_defaults(func=cmd_status)

    p = with_path(sub.add_parser("scan", help="Run applicable security scanners and write reports"))
    p.add_argument("--tool", action="append", choices=["gitleaks", "semgrep", "osv-scanner", "trivy"],
                   help="Run only this scanner (repeatable). Default: scanners enabled in config.")
    p.add_argument("--report-dir", help="Directory for reports (default: PATH/.uds/reports)")
    p.add_argument("--format", default="json,html", help="Comma-separated: json,html,sarif (default: json,html)")
    p.add_argument("--allow-network", action="store_true",
                   help="Allow scanners that send package metadata to external services (OSV-Scanner)")
    p.add_argument("--fail-on", choices=FAIL_ON_LEVELS, help="Exit 1 when findings reach this severity")
    p.add_argument("--require-complete", action="store_true",
                   help="Exit 2 when an applicable scanner did not run (not installed or skipped)")
    p.add_argument("--no-history", action="store_true", help="Do not record this scan in .uds/history")
    p.add_argument("--json", action="store_true", help="Print a machine-readable summary")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = with_path(sub.add_parser("report", help="Regenerate reports from scan history"))
    p.add_argument("--scan", default="latest", help="Scan id, 'latest' or 'previous'")
    p.add_argument("--report-dir")
    p.add_argument("--format", default="json,html")
    p.set_defaults(func=cmd_report)

    p = with_path(sub.add_parser("dashboard", help="Show (or open) the latest HTML dashboard"))
    p.add_argument("--report-dir")
    p.add_argument("--open", action="store_true", help="Open the dashboard in the default browser")
    p.set_defaults(func=cmd_dashboard)

    p = with_path(sub.add_parser("history", help="List previous scans"))
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_history)

    p = with_path(sub.add_parser("compare", help="Compare two scans from history"))
    p.add_argument("--base", default="previous")
    p.add_argument("--head", default="latest")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("policy", help="Show or test the effective security policy")
    psub = p.add_subparsers(dest="policy_command", required=True)
    with_path(psub.add_parser("show", help="Print global rules and project policy")).set_defaults(func=cmd_policy)
    pc = with_path(psub.add_parser("check", help="Evaluate a command or file write against the policy"))
    group = pc.add_mutually_exclusive_group(required=True)
    group.add_argument("--command", dest="command_text", help="Shell command to evaluate")
    group.add_argument("--write", help="Relative path of a file about to be written")
    pc.add_argument("--content-file", help="File whose content would be written (with --write)")
    pc.set_defaults(func=cmd_policy)

    sub.add_parser("scanners", help="List supported scanners, versions and install sources").set_defaults(func=cmd_scanners)

    from universal_dev_security import cli_extra
    cli_extra.register(sub, with_path)
    return parser


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
            except (AttributeError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except (ValueError, FileNotFoundError, NotADirectoryError) as exc:
        _err(str(exc))
        return EXIT_ERROR
    except PermissionError as exc:
        _err(f"Permission denied: {exc.filename or ''}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _err("Interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
