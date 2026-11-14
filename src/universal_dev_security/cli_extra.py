"""CLI commands for integrations, Git protection, recovery, fixes, testing and updates."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _out(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _project(path: str) -> Path:
    target = Path(path).expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"Not an existing directory: {target}")
    return target


def _print_plan(result: dict[str, Any], apply: bool) -> None:
    if not result["changes"]:
        print("No changes needed.")
    for change in result["changes"]:
        print(f"{change['action'].upper()}: {change['path']}")
        if not apply and change.get("diff"):
            print(change["diff"])
    if apply and result.get("checkpoint"):
        print(f"Applied. Recovery checkpoint: {result['checkpoint']} (undo with `uds rollback {result['checkpoint']}`)")
    elif not apply and result["changes"]:
        print("Dry run only. Re-run with --apply to make these changes.")
    for note in result.get("notes", []):
        print(f"note: {note}")
    for conflict in result.get("conflicts", []):
        print(f"conflict: {conflict['path']}: {conflict['message']}")


# -- hooks runtime -----------------------------------------------------------

def cmd_hook(args: argparse.Namespace) -> int:
    if args.hook_name == "claude-code":
        from universal_dev_security.integrations.claude_code import run_hook

        code, output = run_hook(sys.stdin.read())
        if output:
            print(output)
        return code
    from universal_dev_security import gitguard

    try:
        if args.hook_name == "git-pre-commit":
            code, message = gitguard.pre_commit(Path.cwd())
        else:
            remote = args.hook_args[0] if args.hook_args else "origin"
            code, message = gitguard.pre_push(Path.cwd(), remote, sys.stdin.read())
    except Exception as exc:  # noqa: BLE001 - fail closed
        print(f"UDS: security check failed ({type(exc).__name__}); blocking to be safe.", file=sys.stderr)
        return EXIT_FINDINGS
    print(message, file=sys.stderr)
    return code


def cmd_guard(args: argparse.Namespace) -> int:
    from universal_dev_security.integrations.agents import guard

    code, payload = guard(sys.stdin.read(), str(Path(args.project).expanduser().resolve()))
    _out(payload)
    return code


# -- installation commands ------------------------------------------------------

def cmd_hooks(args: argparse.Namespace) -> int:
    from universal_dev_security import gitguard

    root = _project(args.path)
    try:
        if args.hooks_command == "status":
            _out(gitguard.hooks_status(root))
            return EXIT_OK
        python = sys.executable if args.python_path else None
        result = gitguard.install_hooks(root, apply=args.apply, uninstall=args.hooks_command == "uninstall",
                                        python=python)
    except gitguard.GitError as exc:
        print(f"uds: {exc}", file=sys.stderr)
        return EXIT_ERROR
    _print_plan(result, args.apply)
    return EXIT_FINDINGS if result.get("conflicts") else EXIT_OK


def cmd_integrate(args: argparse.Namespace) -> int:
    root = _project(args.path)
    if args.target == "claude-code":
        from universal_dev_security.integrations import claude_code

        result = claude_code.install(root, apply=args.apply, remove=args.remove, local=args.local,
                                     use_python_path=args.python_path)
    elif args.target == "github":
        from universal_dev_security.integrations import github

        result = github.install(root, apply=args.apply, remove=args.remove, branch=args.branch,
                                fail_on=args.fail_on, uds_spec=args.uds_spec)
    else:
        from universal_dev_security.integrations import vscode

        result = vscode.install(root, apply=args.apply, remove=args.remove)
    if args.json:
        _out(result)
    else:
        _print_plan(result, args.apply)
    return EXIT_OK


# -- recovery ---------------------------------------------------------------------

def cmd_checkpoint(args: argparse.Namespace) -> int:
    from universal_dev_security.recovery import RecoveryManager

    manager = RecoveryManager(_project(args.path))
    if args.checkpoint_command == "list":
        _out(manager.list())
        return EXIT_OK
    checkpoint = manager.create(args.label or "manual checkpoint", args.files)
    manager.seal(checkpoint)
    _out({"checkpoint": checkpoint, "files": args.files})
    return EXIT_OK


def cmd_rollback(args: argparse.Namespace) -> int:
    from universal_dev_security.recovery import RecoveryManager

    result = RecoveryManager(_project(args.path)).restore(args.checkpoint, force=args.force)
    _out(result)
    return EXIT_OK if result["status"] == "restored" else EXIT_FINDINGS


# -- fixes and tests ------------------------------------------------------------

def cmd_fix(args: argparse.Namespace) -> int:
    from universal_dev_security.config import load_config
    from universal_dev_security.fixes import apply_fixes, manual_recommendations, plan_fixes
    from universal_dev_security.history import list_scans, load_scan

    root = _project(args.path)
    config = load_config(root)
    latest = load_scan(root, "latest") if list_scans(root) else None
    if not args.apply:
        _out({"automatic_fixes": plan_fixes(root), "manual_recommendations": manual_recommendations(latest),
              "note": "Dry run. Use --apply for low-risk fixes; add --include-medium for medium-risk fixes."})
        return EXIT_OK
    result = apply_fixes(root, config, include_medium=args.include_medium, run_test_suite=not args.skip_tests,
                         approved=args.approve)
    _out(result)
    return EXIT_OK if result["status"] in ("applied", "nothing_to_do") else EXIT_FINDINGS


def cmd_test(args: argparse.Namespace) -> int:
    from universal_dev_security.config import load_config
    from universal_dev_security.testing import run_tests

    root = _project(args.path)
    result = run_tests(root, load_config(root))
    _out(result)
    return {"passed": EXIT_OK, "not_configured": EXIT_FINDINGS}.get(result["status"], EXIT_ERROR)


# -- updates ------------------------------------------------------------------------

def cmd_update(args: argparse.Namespace) -> int:
    from universal_dev_security.updates import check_uds_update, scanner_status

    if args.update_command == "scanners":
        _out(scanner_status())
        return EXIT_OK
    result = check_uds_update(args.source)
    _out(result)
    return EXIT_ERROR if result["status"] == "error" else EXIT_OK


def register(sub: Any, with_path: Callable[[argparse.ArgumentParser], argparse.ArgumentParser]) -> None:
    p = sub.add_parser("hook", help="Hook entry points (called by Git and Claude Code)")
    p.add_argument("hook_name", choices=["claude-code", "git-pre-commit", "git-pre-push"])
    p.add_argument("hook_args", nargs="*")
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("guard", help="Policy decision for AI agents: JSON action on stdin, decision on stdout")
    p.add_argument("--project", default=".", help="Project root (default: current directory)")
    p.set_defaults(func=cmd_guard)

    p = sub.add_parser("hooks", help="Install, remove or inspect UDS Git hooks")
    hsub = p.add_subparsers(dest="hooks_command", required=True)
    for name in ("install", "uninstall"):
        hp = with_path(hsub.add_parser(name))
        hp.add_argument("--apply", action="store_true", help="Make the change (default is a dry run)")
        # Git hooks live in .git/hooks, which is never committed, so embedding this machine's
        # interpreter path is safe and avoids blocking commits when `uds` is not on PATH
        # (e.g. committing from an editor without the virtual environment activated).
        hp.add_argument("--path-only", dest="python_path", action="store_false",
                        help="Rely only on `uds` from PATH instead of embedding this Python interpreter")
        hp.add_argument("--python-path", dest="python_path", action="store_true",
                        help="Embed this Python interpreter (default; kept for compatibility)")
        hp.set_defaults(func=cmd_hooks, python_path=True)
    with_path(hsub.add_parser("status")).set_defaults(func=cmd_hooks, apply=False, python_path=False)

    p = sub.add_parser("integrate", help="Set up Claude Code, GitHub Actions or VS Code integration")
    p.add_argument("target", choices=["claude-code", "github", "vscode"])
    with_path(p)
    p.add_argument("--apply", action="store_true", help="Make the change (default is a dry run with a diff)")
    p.add_argument("--remove", action="store_true", help="Remove UDS-owned configuration only")
    p.add_argument("--local", action="store_true", help="Claude Code: write .claude/settings.local.json")
    p.add_argument("--python-path", action="store_true", help="Claude Code: embed this interpreter path in the hook")
    p.add_argument("--branch", default="main", help="GitHub: default branch for push scans")
    p.add_argument("--fail-on", default="high", help="GitHub: severity threshold that fails the check")
    p.add_argument("--uds-spec", default="universal-dev-security", help="GitHub: pip install spec for UDS")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_integrate)

    p = sub.add_parser("checkpoint", help="Create or list recovery checkpoints")
    csub = p.add_subparsers(dest="checkpoint_command", required=True)
    cp = with_path(csub.add_parser("create"))
    cp.add_argument("--label")
    cp.add_argument("--file", dest="files", action="append", required=True, help="Project-relative file (repeatable)")
    cp.set_defaults(func=cmd_checkpoint)
    with_path(csub.add_parser("list")).set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("rollback", help="Restore a recovery checkpoint (keeps later user edits unless --force)")
    p.add_argument("checkpoint")
    with_path(p)
    p.add_argument("--force", action="store_true", help="Also overwrite files changed after the checkpoint")
    p.set_defaults(func=cmd_rollback)

    p = with_path(sub.add_parser("fix", help="Plan or apply safe, reversible automatic fixes"))
    p.add_argument("--apply", action="store_true")
    p.add_argument("--include-medium", action="store_true")
    p.add_argument("--skip-tests", action="store_true", help="Do not run tests before/after fixing")
    p.add_argument("--approve", action="store_true", help="Explicit approval when automatic fixes are disabled by config")
    p.set_defaults(func=cmd_fix)

    with_path(sub.add_parser("test", help="Detect and run the project's test suite")).set_defaults(func=cmd_test)

    p = sub.add_parser("update", help="Check for UDS updates or show scanner versions (never installs)")
    usub = p.add_subparsers(dest="update_command", required=True)
    up = usub.add_parser("check")
    up.add_argument("--source", help="'pypi' or 'github:OWNER/REPO' (network request only when given)")
    up.set_defaults(func=cmd_update)
    usub.add_parser("scanners").set_defaults(func=cmd_update)
