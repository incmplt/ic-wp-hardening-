from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from . import __version__


STATUSES = ("PASS", "INFO", "WARN", "FAIL")


# Report rows are carried as immutable dataclasses so every check can return
# the same structured shape before the final Markdown/JSON rendering step.
@dataclass(frozen=True)
class Finding:
    check: str
    status: str
    message: str
    detail: str = ""
    path: str = ""
    remediation: str = ""
    evidence: str = ""
    source: str = "static"


@dataclass(frozen=True)
class Plugin:
    slug: str
    name: str
    version: str
    path: Path


@dataclass(frozen=True)
class Theme:
    slug: str
    name: str
    version: str
    path: Path


@dataclass(frozen=True)
class CveTarget:
    kind: str
    slug: str
    name: str
    version: str
    path: str = ""


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.wp_root.resolve()
    document_root = args.document_root.resolve() if args.document_root else root
    load_env_files(root)

    # Collect findings in the same order they should appear in the report:
    # target validation first, then WordPress, extension, CVE, filesystem, and PHP checks.
    findings: list[Finding] = []
    findings.extend(check_wordpress_root(root))
    use_wp_cli, wp_cli_findings = resolve_wp_cli(args.use_wp_cli, args.wp_cli_bin)
    findings.extend(wp_cli_findings)

    if any(f.check == "wordpress-root" and f.status == "FAIL" for f in findings):
        report = render_report(root, findings, args.format)
        write_report(args.output, report)
        return exit_code(args.fail_on, findings)

    findings.extend(check_core_version(root, args.online, args.timeout))
    findings.extend(check_wp_config(root, use_wp_cli, args.wp_cli_bin, args.timeout))

    # Prefer WP-CLI for plugin state because it can report activation, updates,
    # and repository metadata. Fall back to static header parsing when unavailable.
    plugins: list[Plugin] | None = None
    if use_wp_cli:
        plugins, plugin_findings = check_plugins_with_wp_cli(
            root,
            args.wp_cli_bin,
            args.online,
            args.timeout,
            args.vuln_db,
        )
        findings.extend(plugin_findings)
    if plugins is None:
        plugins = discover_plugins(root)
        findings.extend(check_plugins(plugins, args.online, args.timeout, args.vuln_db))

    findings.extend(check_themes(root, use_wp_cli, args.wp_cli_bin, args.online, args.timeout))
    themes = discover_themes(root)
    findings.extend(check_mu_plugins(root))
    if args.cve_check:
        findings.extend(
            check_cves(
                root=root,
                core_version=read_wordpress_version(root / "wp-includes" / "version.php"),
                plugins=plugins,
                themes=themes,
                cve_map_path=args.cve_map,
                cve_match=args.cve_match,
                cve_max_results=args.cve_max_results,
                cve_max_keyword_targets=args.cve_max_keyword_targets,
                cve_cache_path=args.cve_cache,
                nvd_api_key=os.environ.get("NVD_API_KEY", ""),
                nvd_delay=args.nvd_delay,
                timeout=args.timeout,
            )
        )
    findings.extend(
        check_wp_cli_checksums(
            root,
            use_wp_cli,
            args.wp_cli_bin,
            args.verify_checksums,
            args.timeout,
        )
    )
    findings.extend(
        check_exposed_files(
            scan_root=document_root,
            max_findings=args.max_file_scan_findings,
            wp_root=root,
        )
    )
    findings.extend(check_uploads_php(root, args.max_file_scan_findings))
    findings.extend(check_permissions(root, args.max_permission_findings))
    findings.extend(check_php_settings(args.php_ini, args.php_bin))

    report = render_report(root, findings, args.format)
    write_report(args.output, report)
    return exit_code(args.fail_on, findings)


def build_parser() -> argparse.ArgumentParser:
    # Define the CLI surface in one place so main() can focus on orchestration.
    parser = argparse.ArgumentParser(
        prog="ic-wp-hardening",
        description="Check a local WordPress installation and output a security report.",
    )
    parser.add_argument("wp_root", type=Path, help="Path to the WordPress installation root.")
    parser.add_argument("-o", "--output", type=Path, help="Write report to this file.")
    parser.add_argument(
        "--document-root",
        type=Path,
        help=(
            "Path to the web server DocumentRoot for exposed-file checks. "
            "Defaults to the WordPress root."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Report output format. Default: markdown.",
    )
    parser.add_argument(
        "--use-wp-cli",
        choices=("auto", "always", "never"),
        default="auto",
        help="Use WP-CLI for richer local WordPress state when available. Default: auto.",
    )
    parser.add_argument("--wp-cli-bin", default="wp", help="WP-CLI binary. Default: wp.")
    parser.add_argument(
        "--online",
        action="store_true",
        help="Use wordpress.org APIs for WordPress core/plugin update checks.",
    )
    parser.add_argument(
        "--vuln-db",
        type=Path,
        help="Local JSON vulnerability database for plugin checks.",
    )
    parser.add_argument(
        "--php-ini",
        type=Path,
        help="Path to php.ini. If omitted, the tool tries `php -i`.",
    )
    parser.add_argument("--php-bin", default="php", help="PHP binary used when --php-ini is omitted.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Network/process timeout in seconds. Default: 8.",
    )
    parser.add_argument(
        "--verify-checksums",
        choices=("none", "core", "plugins", "all"),
        default="none",
        help="Run WP-CLI checksum verification. Requires WP-CLI and network. Default: none.",
    )
    parser.add_argument(
        "--cve-check",
        action="store_true",
        help="Search NVD for CVEs related to WordPress core, plugins, and themes.",
    )
    parser.add_argument(
        "--cve-match",
        choices=("cpe", "keyword", "both"),
        default="cpe",
        help="CVE search strategy. Keyword fallback can be noisy and request-heavy. Default: cpe.",
    )
    parser.add_argument(
        "--cve-map",
        type=Path,
        help="JSON file mapping WordPress core/plugins/themes to CPE names or templates.",
    )
    parser.add_argument(
        "--cve-cache",
        type=Path,
        help="Optional JSON cache for NVD API responses.",
    )
    parser.add_argument(
        "--cve-max-results",
        type=int,
        default=20,
        help="Maximum NVD CVE records to request per target. Default: 20.",
    )
    parser.add_argument(
        "--cve-max-keyword-targets",
        type=int,
        default=20,
        help="Maximum plugin/theme targets searched with keyword fallback. Default: 20.",
    )
    parser.add_argument(
        "--nvd-delay",
        type=float,
        help="Delay between NVD API requests. Default: 0.6s with API key, 6.0s without.",
    )
    parser.add_argument(
        "--max-permission-findings",
        type=int,
        default=25,
        help="Maximum individual permission paths shown in the report. Default: 25.",
    )
    parser.add_argument(
        "--max-file-scan-findings",
        type=int,
        default=25,
        help="Maximum exposed-file/upload PHP paths shown in the report. Default: 25.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("fail", "warn", "never"),
        default="fail",
        help="Exit non-zero when findings reach this level. Default: fail.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def load_env_files(root: Path) -> None:
    # Later candidates are still considered, but existing environment variables
    # are not overwritten by load_env_file().
    candidates: list[Path] = []
    configured = os.environ.get("IC_WP_HARDENING_ENV_FILE", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend([Path.cwd() / ".env", root / ".env"])

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        load_env_file(resolved)


def load_env_file(path: Path) -> None:
    # Minimal dotenv parser: supports KEY=value and export KEY=value, while
    # ignoring comments, malformed keys, and variables already set by the caller.
    if not path.exists() or not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        if key in os.environ:
            continue
        os.environ[key] = parse_env_value(value)


def parse_env_value(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value.split(" #", 1)[0].strip()


def resolve_wp_cli(mode: str, wp_cli_bin: str) -> tuple[bool, list[Finding]]:
    # Resolve the user's WP-CLI preference into a boolean used by checks plus a
    # finding that explains whether richer WP-CLI-backed checks will run.
    if mode == "never":
        return False, [Finding("wp-cli", "INFO", "WP-CLI integration is disabled.", source="wp-cli")]

    if is_command_available(wp_cli_bin):
        return True, [Finding("wp-cli", "PASS", f"WP-CLI integration enabled: {wp_cli_bin}", source="wp-cli")]

    finding = Finding(
        "wp-cli",
        "WARN" if mode == "always" else "INFO",
        f"WP-CLI binary was not found: {wp_cli_bin}",
        "Static checks will be used where possible.",
        source="wp-cli",
    )
    return False, [finding]


def is_command_available(command: str) -> bool:
    if os.sep in command:
        return Path(command).exists()
    return shutil.which(command) is not None


def run_wp_cli_json(root: Path, wp_cli_bin: str, args: list[str], timeout: float) -> tuple[Any | None, str]:
    # WP-CLI JSON calls share the same subprocess/error handling and return an
    # error string instead of raising so the CLI can continue collecting findings.
    command = [wp_cli_bin, f"--path={root}", *args]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit code {completed.returncode}"
        return None, detail
    stdout = completed.stdout.strip()
    if not stdout:
        return [], ""
    try:
        return json.loads(stdout), ""
    except json.JSONDecodeError as exc:
        return None, f"Could not parse WP-CLI JSON output: {exc}"


def run_wp_cli_plain(root: Path, wp_cli_bin: str, args: list[str], timeout: float) -> tuple[bool, str]:
    command = [wp_cli_bin, f"--path={root}", *args]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = (completed.stdout.strip() or completed.stderr.strip()).strip()
    return completed.returncode == 0, output


def check_wordpress_root(root: Path) -> list[Finding]:
    required = [
        root / "wp-includes" / "version.php",
        root / "wp-admin",
        root / "wp-content",
    ]
    missing = [path.relative_to(root).as_posix() for path in required if not path.exists()]
    if not root.exists():
        return [
            Finding(
                "wordpress-root",
                "FAIL",
                "WordPress root does not exist.",
                path=str(root),
            )
        ]
    if missing:
        return [
            Finding(
                "wordpress-root",
                "FAIL",
                "Target does not look like a WordPress root.",
                "Missing: " + ", ".join(missing),
                path=str(root),
            )
        ]
    return [Finding("wordpress-root", "PASS", "WordPress root structure was detected.", path=str(root))]


def check_core_version(root: Path, online: bool, timeout: float) -> list[Finding]:
    # Static version detection always runs; the online latest-version comparison
    # is opt-in to avoid unexpected network calls.
    version_file = root / "wp-includes" / "version.php"
    version = read_wordpress_version(version_file)
    if not version:
        return [
            Finding(
                "core-version",
                "FAIL",
                "Could not read WordPress core version.",
                path=str(version_file),
            )
        ]

    findings = [
        Finding(
            "core-version",
            "INFO",
            f"Installed WordPress version: {version}",
            path=str(version_file),
        )
    ]

    if not online:
        findings.append(
            Finding(
                "core-update",
                "INFO",
                "Skipped online WordPress core update check.",
                "Run with --online to compare against wordpress.org.",
            )
        )
        return findings

    try:
        latest = fetch_latest_wordpress_version(timeout)
    except Exception as exc:  # noqa: BLE001 - this is a CLI report surface.
        return findings + [
            Finding(
                "core-update",
                "WARN",
                "Could not complete WordPress core update check.",
                str(exc),
            )
        ]

    if latest and compare_versions(version, latest) < 0:
        findings.append(
            Finding(
                "core-update",
                "FAIL",
                f"WordPress core appears outdated: installed {version}, latest {latest}.",
            )
        )
    elif latest:
        findings.append(Finding("core-update", "PASS", f"WordPress core is current: {version}."))
    else:
        findings.append(Finding("core-update", "WARN", "wordpress.org did not return a latest version."))
    return findings


def read_wordpress_version(version_file: Path) -> str:
    try:
        text = version_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", text)
    return match.group(1).strip() if match else ""


def fetch_latest_wordpress_version(timeout: float) -> str:
    # wordpress.org may return multiple offers; choose the highest advertised
    # current version among upgrade/latest responses.
    with urllib.request.urlopen("https://api.wordpress.org/core/version-check/1.7/", timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    offers = payload.get("offers") or []
    versions = [offer.get("current") for offer in offers if offer.get("response") in {"upgrade", "latest"}]
    versions = [version for version in versions if isinstance(version, str)]
    if not versions:
        return ""
    return sorted(versions, key=version_key)[-1]


def check_wp_config(root: Path, use_wp_cli: bool, wp_cli_bin: str, timeout: float) -> list[Finding]:
    # Combine static wp-config.php parsing with optional WP-CLI confirmation.
    # Static parsing provides the actual hardening checks even without WordPress bootstrapping.
    config_path = find_wp_config(root)
    if config_path is None:
        return [
            Finding(
                "wp-config",
                "FAIL",
                "wp-config.php was not found in the WordPress root or its parent directory.",
                remediation="Confirm the target path or restore wp-config.php.",
            )
        ]

    values = parse_wp_config_file(config_path)
    findings = evaluate_wp_config_values(values, config_path)

    if use_wp_cli:
        payload, error = run_wp_cli_json(root, wp_cli_bin, ["config", "list", "--format=json"], timeout)
        if error:
            findings.append(
                Finding(
                    "wp-config",
                    "WARN",
                    "Could not read wp-config.php through WP-CLI.",
                    error,
                    source="wp-cli",
                )
            )
        elif isinstance(payload, list):
            keys = {str(item.get("key")) for item in payload if isinstance(item, dict)}
            findings.append(
                Finding(
                    "wp-config",
                    "PASS",
                    f"WP-CLI read {len(keys)} wp-config entrie(s).",
                    source="wp-cli",
                )
            )
    return findings


def find_wp_config(root: Path) -> Path | None:
    for candidate in (root / "wp-config.php", root.parent / "wp-config.php"):
        if candidate.exists():
            return candidate
    return None


def parse_wp_config_file(path: Path) -> dict[str, str]:
    # Extract simple define('KEY', value) constants and $table_prefix without
    # executing PHP code from the target site.
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}

    values: dict[str, str] = {}
    define_pattern = re.compile(
        r"define\s*\(\s*['\"](?P<key>[A-Z0-9_]+)['\"]\s*,\s*(?P<value>.*?)\s*\)\s*;",
        re.IGNORECASE | re.DOTALL,
    )
    for match in define_pattern.finditer(text):
        values[match.group("key")] = normalize_php_literal(match.group("value"))

    prefix_match = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", text)
    if prefix_match:
        values["table_prefix"] = prefix_match.group(1)
    return values


def normalize_php_literal(value: str) -> str:
    cleaned = value.strip().rstrip(";").strip()
    if cleaned.lower() in {"true", "false"}:
        return cleaned.lower()
    if (cleaned.startswith("'") and cleaned.endswith("'")) or (
        cleaned.startswith('"') and cleaned.endswith('"')
    ):
        return cleaned[1:-1]
    return cleaned


def evaluate_wp_config_values(values: dict[str, str], config_path: Path) -> list[Finding]:
    # Evaluate common production hardening signals in wp-config.php and keep each
    # condition as a separate finding for clearer remediation.
    findings: list[Finding] = [
        Finding("wp-config", "PASS", "wp-config.php was found.", path=str(config_path))
    ]

    disallow_file_edit = values.get("DISALLOW_FILE_EDIT")
    if normalize_php_bool(disallow_file_edit or "") == "on":
        findings.append(Finding("wp-config", "PASS", "DISALLOW_FILE_EDIT is enabled.", path=str(config_path)))
    else:
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "DISALLOW_FILE_EDIT is not enabled.",
                remediation="Add define('DISALLOW_FILE_EDIT', true); to wp-config.php.",
                path=str(config_path),
            )
        )

    disallow_file_mods = values.get("DISALLOW_FILE_MODS")
    if disallow_file_mods is None:
        findings.append(
            Finding(
                "wp-config",
                "INFO",
                "DISALLOW_FILE_MODS is not defined.",
                path=str(config_path),
            )
        )
    elif normalize_php_bool(disallow_file_mods) == "on":
        findings.append(
            Finding("wp-config", "PASS", "DISALLOW_FILE_MODS is enabled.", path=str(config_path))
        )
    else:
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "DISALLOW_FILE_MODS is disabled.",
                "Plugin/theme installs and updates may be allowed from wp-admin.",
                remediation=(
                    "Enable DISALLOW_FILE_MODS on locked-down production sites "
                    "if operationally feasible."
                ),
                path=str(config_path),
            )
        )

    wp_debug = values.get("WP_DEBUG")
    if wp_debug is None:
        findings.append(Finding("wp-config", "INFO", "WP_DEBUG is not defined.", path=str(config_path)))
    elif normalize_php_bool(wp_debug) == "on":
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "WP_DEBUG is enabled.",
                remediation="Disable WP_DEBUG on production sites.",
                path=str(config_path),
            )
        )
    else:
        findings.append(Finding("wp-config", "PASS", "WP_DEBUG is disabled.", path=str(config_path)))

    wp_debug_log = values.get("WP_DEBUG_LOG")
    if wp_debug_log is None:
        findings.append(
            Finding("wp-config", "INFO", "WP_DEBUG_LOG is not defined.", path=str(config_path))
        )
    elif normalize_php_bool(wp_debug_log) == "on":
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "WP_DEBUG_LOG is enabled.",
                "Debug logs can disclose sensitive details if exposed under wp-content.",
                remediation=(
                    "Disable WP_DEBUG_LOG on production sites or ensure logs are not "
                    "web-accessible."
                ),
                path=str(config_path),
            )
        )
    else:
        findings.append(
            Finding("wp-config", "PASS", "WP_DEBUG_LOG is disabled.", path=str(config_path))
        )

    script_debug = values.get("SCRIPT_DEBUG")
    if script_debug is None:
        findings.append(
            Finding("wp-config", "INFO", "SCRIPT_DEBUG is not defined.", path=str(config_path))
        )
    elif normalize_php_bool(script_debug) == "on":
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "SCRIPT_DEBUG is enabled.",
                remediation="Disable SCRIPT_DEBUG on production sites.",
                path=str(config_path),
            )
        )
    else:
        findings.append(
            Finding("wp-config", "PASS", "SCRIPT_DEBUG is disabled.", path=str(config_path))
        )

    force_ssl_admin = values.get("FORCE_SSL_ADMIN")
    if force_ssl_admin is None:
        findings.append(Finding("wp-config", "INFO", "FORCE_SSL_ADMIN is not defined.", path=str(config_path)))
    elif normalize_php_bool(force_ssl_admin) == "on":
        findings.append(Finding("wp-config", "PASS", "FORCE_SSL_ADMIN is enabled.", path=str(config_path)))
    else:
        findings.append(Finding("wp-config", "WARN", "FORCE_SSL_ADMIN is disabled.", path=str(config_path)))

    automatic_updater_disabled = values.get("AUTOMATIC_UPDATER_DISABLED")
    if automatic_updater_disabled is None:
        findings.append(
            Finding(
                "wp-config",
                "INFO",
                "AUTOMATIC_UPDATER_DISABLED is not defined.",
                path=str(config_path),
            )
        )
    elif normalize_php_bool(automatic_updater_disabled) == "on":
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "AUTOMATIC_UPDATER_DISABLED is enabled.",
                remediation=(
                    "Keep automatic updates enabled unless updates are handled by another "
                    "controlled process."
                ),
                path=str(config_path),
            )
        )
    else:
        findings.append(
            Finding(
                "wp-config",
                "PASS",
                "AUTOMATIC_UPDATER_DISABLED is disabled.",
                path=str(config_path),
            )
        )

    wp_auto_update_core = values.get("WP_AUTO_UPDATE_CORE")
    if wp_auto_update_core is None:
        findings.append(
            Finding(
                "wp-config",
                "INFO",
                "WP_AUTO_UPDATE_CORE is not defined.",
                path=str(config_path),
            )
        )
    elif normalize_php_bool(wp_auto_update_core) == "off":
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "WordPress core automatic updates are disabled.",
                remediation=(
                    "Allow at least minor core automatic updates or document the manual "
                    "patch process."
                ),
                path=str(config_path),
            )
        )
    else:
        findings.append(
            Finding(
                "wp-config",
                "PASS",
                f"WP_AUTO_UPDATE_CORE is configured: {wp_auto_update_core}.",
                path=str(config_path),
            )
        )

    environment_type = values.get("WP_ENVIRONMENT_TYPE")
    if environment_type is None:
        findings.append(
            Finding(
                "wp-config",
                "INFO",
                "WP_ENVIRONMENT_TYPE is not defined.",
                path=str(config_path),
            )
        )
    elif environment_type.lower() == "production":
        findings.append(
            Finding(
                "wp-config",
                "PASS",
                "WP_ENVIRONMENT_TYPE is production.",
                path=str(config_path),
            )
        )
    else:
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                f"WP_ENVIRONMENT_TYPE is {environment_type}.",
                "Production sites should not identify as local, development, or staging.",
                remediation="Set WP_ENVIRONMENT_TYPE to production on live sites.",
                path=str(config_path),
            )
        )

    if values.get("table_prefix") == "wp_":
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                "Database table prefix is the default wp_.",
                "This is a minor hardening signal, not a primary security control.",
                path=str(config_path),
            )
        )
    elif "table_prefix" in values:
        findings.append(Finding("wp-config", "PASS", "Database table prefix is customized.", path=str(config_path)))

    if values.get("DB_PASSWORD", "not-empty") == "":
        findings.append(
            Finding(
                "wp-config",
                "FAIL",
                "DB_PASSWORD is empty.",
                remediation="Use a strong database password and least-privilege database account.",
                path=str(config_path),
            )
        )

    salt_keys = [
        "AUTH_KEY",
        "SECURE_AUTH_KEY",
        "LOGGED_IN_KEY",
        "NONCE_KEY",
        "AUTH_SALT",
        "SECURE_AUTH_SALT",
        "LOGGED_IN_SALT",
        "NONCE_SALT",
    ]
    missing_salts = [key for key in salt_keys if key not in values]
    weak_salts = [
        key
        for key in salt_keys
        if key in values and ("put your unique phrase here" in values[key].lower() or len(values[key]) < 32)
    ]
    if missing_salts:
        findings.append(
            Finding(
                "wp-config",
                "WARN",
                f"Missing {len(missing_salts)} authentication key/salt value(s).",
                ", ".join(missing_salts),
                remediation="Generate fresh keys from the WordPress.org secret-key service.",
                path=str(config_path),
            )
        )
    elif weak_salts:
        findings.append(
            Finding(
                "wp-config",
                "FAIL",
                "Weak placeholder authentication key/salt value(s) detected.",
                ", ".join(weak_salts),
                remediation="Replace placeholder salts with strong random values.",
                path=str(config_path),
            )
        )
    else:
        findings.append(Finding("wp-config", "PASS", "Authentication keys and salts are present.", path=str(config_path)))

    return findings


def discover_plugins(root: Path) -> list[Plugin]:
    # WordPress plugins can be a single PHP file or a directory containing a
    # plugin header; scan both forms and stop at the first header per directory.
    plugins_dir = root / "wp-content" / "plugins"
    if not plugins_dir.exists():
        return []

    plugins: list[Plugin] = []
    for php_file in sorted(plugins_dir.glob("*.php")):
        plugin = parse_plugin_file(php_file, php_file.stem)
        if plugin:
            plugins.append(plugin)

    for child in sorted(path for path in plugins_dir.iterdir() if path.is_dir()):
        for php_file in sorted(child.glob("*.php")):
            plugin = parse_plugin_file(php_file, child.name)
            if plugin:
                plugins.append(plugin)
                break
    return plugins


def parse_plugin_file(path: Path, slug: str) -> Plugin | None:
    # Only the plugin header block is needed, so cap the read size to keep scans cheap.
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")[:8192]
    except OSError:
        return None

    name = parse_header(text, "Plugin Name")
    if not name:
        return None
    version = parse_header(text, "Version") or "unknown"
    return Plugin(slug=slug, name=name, version=version, path=path)


def parse_header(text: str, header: str) -> str:
    pattern = rf"^[ \t/*#@]*{re.escape(header)}\s*:\s*(.+?)\s*$"
    match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


def check_plugins(
    plugins: list[Plugin],
    online: bool,
    timeout: float,
    vuln_db_path: Path | None,
) -> list[Finding]:
    # Static plugin checks report inventory, optional local vulnerability matches,
    # and optional wordpress.org update status.
    findings: list[Finding] = []
    if not plugins:
        findings.append(Finding("plugins", "INFO", "No plugins were detected."))
    else:
        findings.append(Finding("plugins", "INFO", f"Detected {len(plugins)} plugin(s)."))

    vulnerability_entries = load_vulnerability_db(vuln_db_path)
    for plugin in plugins:
        findings.append(
            Finding(
                "plugin-inventory",
                "INFO",
                f"{plugin.name} ({plugin.slug}) version {plugin.version}",
                path=str(plugin.path),
            )
        )
        findings.extend(check_plugin_vulnerabilities(plugin, vulnerability_entries))

        if online:
            try:
                latest = fetch_latest_plugin_version(plugin.slug, timeout)
            except Exception as exc:  # noqa: BLE001 - this is a CLI report surface.
                findings.append(
                    Finding(
                        "plugin-update",
                        "WARN",
                        f"Could not check updates for plugin {plugin.slug}.",
                        str(exc),
                        path=str(plugin.path),
                    )
                )
                continue
            if latest and plugin.version != "unknown" and compare_versions(plugin.version, latest) < 0:
                findings.append(
                    Finding(
                        "plugin-update",
                        "WARN",
                        f"Plugin {plugin.slug} appears outdated: installed {plugin.version}, latest {latest}.",
                        path=str(plugin.path),
                    )
                )
            elif latest:
                findings.append(
                    Finding("plugin-update", "PASS", f"Plugin {plugin.slug} is current: {plugin.version}.")
                )

    if vuln_db_path is None:
        findings.append(
            Finding(
                "plugin-vulnerabilities",
                "INFO",
                "Skipped plugin vulnerability matching because no --vuln-db was supplied.",
            )
        )
    return findings


def check_plugins_with_wp_cli(
    root: Path,
    wp_cli_bin: str,
    online: bool,
    timeout: float,
    vuln_db_path: Path | None,
) -> tuple[list[Plugin] | None, list[Finding]]:
    # WP-CLI supplies runtime state that static file parsing cannot know, such as
    # active/inactive status, auto-update settings, and repository update data.
    fields = "name,status,update,version,update_version,auto_update,file,title,wporg_status,wporg_last_updated"
    command = ["plugin", "list", f"--fields={fields}", "--format=json"]
    if not online:
        command.append("--skip-update-check")

    payload, error = run_wp_cli_json(root, wp_cli_bin, command, timeout)
    if error:
        return None, [
            Finding(
                "plugins",
                "WARN",
                "Could not read plugin state through WP-CLI.",
                error,
                remediation="Falling back to static plugin header parsing.",
                source="wp-cli",
            )
        ]
    if not isinstance(payload, list):
        return None, [
            Finding(
                "plugins",
                "WARN",
                "WP-CLI plugin list returned an unexpected payload.",
                remediation="Falling back to static plugin header parsing.",
                source="wp-cli",
            )
        ]

    plugins: list[Plugin] = []
    findings: list[Finding] = [
        Finding("plugins", "INFO", f"WP-CLI detected {len(payload)} plugin(s).", source="wp-cli")
    ]
    vulnerability_entries = load_vulnerability_db(vuln_db_path)
    for item in payload:
        if not isinstance(item, dict):
            continue
        slug = str(item.get("name") or "").strip()
        if not slug:
            continue
        file_value = str(item.get("file") or "").strip()
        path = root / "wp-content" / "plugins" / (file_value or slug)
        plugin = Plugin(
            slug=slug,
            name=str(item.get("title") or slug),
            version=str(item.get("version") or "unknown"),
            path=path,
        )
        plugins.append(plugin)

        status = str(item.get("status") or "unknown")
        auto_update = str(item.get("auto_update") or "unknown")
        findings.append(
            Finding(
                "plugin-inventory",
                "INFO",
                f"{plugin.name} ({plugin.slug}) version {plugin.version}",
                f"status: {status}; auto_update: {auto_update}",
                path=str(plugin.path),
                source="wp-cli",
            )
        )
        update = str(item.get("update") or "none")
        update_version = str(item.get("update_version") or "").strip()
        if update == "available":
            findings.append(
                Finding(
                    "plugin-update",
                    "WARN",
                    f"Plugin {plugin.slug} has an update available.",
                    f"installed: {plugin.version}; available: {update_version or 'unknown'}",
                    remediation="Update the plugin after testing compatibility.",
                    path=str(plugin.path),
                    source="wp-cli",
                )
            )
        elif online:
            findings.append(
                Finding("plugin-update", "PASS", f"Plugin {plugin.slug} has no reported update.", source="wp-cli")
            )

        wporg_status = str(item.get("wporg_status") or "").strip()
        if wporg_status and wporg_status not in {"active", "unknown"}:
            findings.append(
                Finding(
                    "plugin-repository",
                    "WARN",
                    f"Plugin {plugin.slug} is not active in the WordPress.org repository.",
                    f"wporg_status: {wporg_status}; last_updated: {item.get('wporg_last_updated') or 'unknown'}",
                    remediation="Review whether the plugin is still maintained.",
                    path=str(plugin.path),
                    source="wp-cli",
                )
            )
        findings.extend(check_plugin_vulnerabilities(plugin, vulnerability_entries))

    if vuln_db_path is None:
        findings.append(
            Finding(
                "plugin-vulnerabilities",
                "INFO",
                "Skipped plugin vulnerability matching because no --vuln-db was supplied.",
                source="wp-cli",
            )
        )
    return plugins, findings


def load_vulnerability_db(path: Path | None) -> list[dict[str, Any]]:
    # Accept both a flat vulnerability list and a {plugins: {slug: [...]}} shape
    # so teams can maintain a small local advisory file without a strict schema.
    if path is None:
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [
            {
                "slug": "*",
                "title": "Could not read vulnerability database",
                "affected": "*",
                "severity": "warn",
                "detail": str(exc),
                "_load_error": True,
            }
        ]
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    if isinstance(payload, dict):
        plugins = payload.get("plugins")
        if isinstance(plugins, dict):
            entries: list[dict[str, Any]] = []
            for slug, plugin_entries in plugins.items():
                if isinstance(plugin_entries, list):
                    for entry in plugin_entries:
                        if isinstance(entry, dict):
                            entries.append({"slug": slug, **entry})
            return entries
        entries = payload.get("vulnerabilities")
        if isinstance(entries, list):
            return [entry for entry in entries if isinstance(entry, dict)]
    return []


def check_plugin_vulnerabilities(plugin: Plugin, entries: list[dict[str, Any]]) -> list[Finding]:
    # Match local advisory entries by plugin slug and version constraint.
    # Unknown plugin versions are treated as potentially affected.
    findings: list[Finding] = []
    for entry in entries:
        slug = str(entry.get("slug", "")).strip()
        if slug not in {plugin.slug, "*"}:
            continue
        if entry.get("_load_error"):
            findings.append(
                Finding(
                    "plugin-vulnerabilities",
                    "WARN",
                    str(entry.get("title")),
                    str(entry.get("detail", "")),
                )
            )
            continue
        affected = str(entry.get("affected", "*")).strip() or "*"
        if plugin.version == "unknown" or version_matches(plugin.version, affected):
            severity = normalize_severity(str(entry.get("severity", "fail")))
            title = str(entry.get("title", "Plugin vulnerability match"))
            fixed_in = str(entry.get("fixed_in", "")).strip()
            url = str(entry.get("url", "")).strip()
            detail_parts = [f"affected: {affected}"]
            if fixed_in:
                detail_parts.append(f"fixed_in: {fixed_in}")
            if url:
                detail_parts.append(f"url: {url}")
            findings.append(
                Finding(
                    "plugin-vulnerabilities",
                    severity,
                    f"{plugin.slug}: {title}",
                    "; ".join(detail_parts),
                    path=str(plugin.path),
                )
            )
    return findings


def fetch_latest_plugin_version(slug: str, timeout: float) -> str:
    # Query the public plugin information endpoint with sections/icons omitted to
    # keep the response small.
    data = urllib.parse.urlencode(
        {
            "action": "plugin_information",
            "request[slug]": slug,
            "request[fields][sections]": "0",
            "request[fields][description]": "0",
            "request[fields][short_description]": "0",
            "request[fields][icons]": "0",
            "request[fields][banners]": "0",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://api.wordpress.org/plugins/info/1.2/",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    version = payload.get("version")
    return version if isinstance(version, str) else ""


def check_themes(root: Path, use_wp_cli: bool, wp_cli_bin: str, online: bool, timeout: float) -> list[Finding]:
    # Prefer WP-CLI for theme activation/update state, but static style.css
    # header parsing still gives useful inventory when WP-CLI cannot run.
    if use_wp_cli:
        wp_cli_findings = check_themes_with_wp_cli(root, wp_cli_bin, online, timeout)
        if wp_cli_findings is not None:
            return wp_cli_findings
    return check_themes_statically(root)


def check_themes_with_wp_cli(
    root: Path,
    wp_cli_bin: str,
    online: bool,
    timeout: float,
) -> list[Finding] | None:
    # WP-CLI can identify inactive themes and update availability, which are not
    # reliable from filesystem inspection alone.
    fields = "name,status,update,version,update_version,auto_update,title"
    command = ["theme", "list", f"--fields={fields}", "--format=json"]
    if not online:
        command.append("--skip-update-check")

    payload, error = run_wp_cli_json(root, wp_cli_bin, command, timeout)
    if error:
        return [
            Finding(
                "themes",
                "WARN",
                "Could not read theme state through WP-CLI.",
                error,
                remediation="Falling back to static theme header parsing.",
                source="wp-cli",
            ),
            *check_themes_statically(root),
        ]
    if not isinstance(payload, list):
        return None

    findings: list[Finding] = [
        Finding("themes", "INFO", f"WP-CLI detected {len(payload)} theme(s).", source="wp-cli")
    ]
    inactive: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        slug = str(item.get("name") or "").strip()
        if not slug:
            continue
        status = str(item.get("status") or "unknown")
        update = str(item.get("update") or "none")
        version = str(item.get("version") or "unknown")
        title = str(item.get("title") or slug)
        path = root / "wp-content" / "themes" / slug
        findings.append(
            Finding(
                "theme-inventory",
                "INFO",
                f"{title} ({slug}) version {version}",
                f"status: {status}; auto_update: {item.get('auto_update') or 'unknown'}",
                path=str(path),
                source="wp-cli",
            )
        )
        if status == "inactive":
            inactive.append(slug)
        if update == "available":
            findings.append(
                Finding(
                    "theme-update",
                    "WARN",
                    f"Theme {slug} has an update available.",
                    f"installed: {version}; available: {item.get('update_version') or 'unknown'}",
                    remediation="Update the theme after testing compatibility.",
                    path=str(path),
                    source="wp-cli",
                )
            )
        elif online:
            findings.append(Finding("theme-update", "PASS", f"Theme {slug} has no reported update.", source="wp-cli"))

    if inactive:
        findings.append(
            Finding(
                "themes",
                "WARN",
                f"{len(inactive)} inactive theme(s) detected.",
                ", ".join(inactive),
                remediation="Remove unused themes after confirming they are not needed for rollback or child themes.",
                source="wp-cli",
            )
        )
    return findings


def check_themes_statically(root: Path) -> list[Finding]:
    # Static theme checks intentionally avoid guessing activation state.
    themes = discover_themes(root)
    if not themes:
        return [Finding("themes", "INFO", "No themes were detected.")]
    findings = [Finding("themes", "INFO", f"Detected {len(themes)} theme(s).")]
    for theme in themes:
        findings.append(
            Finding(
                "theme-inventory",
                "INFO",
                f"{theme.name} ({theme.slug}) version {theme.version}",
                "Theme activation state requires WP-CLI.",
                path=str(theme.path),
            )
        )
    if len(themes) > 2:
        findings.append(
            Finding(
                "themes",
                "INFO",
                f"{len(themes)} themes are present.",
                "Use WP-CLI mode to identify inactive themes accurately.",
            )
        )
    return findings


def discover_themes(root: Path) -> list[Theme]:
    # Theme metadata lives in each theme directory's style.css header.
    themes_dir = root / "wp-content" / "themes"
    if not themes_dir.exists():
        return []
    themes: list[Theme] = []
    for child in sorted(path for path in themes_dir.iterdir() if path.is_dir()):
        style_css = child / "style.css"
        if not style_css.exists():
            continue
        try:
            text = style_css.read_text(encoding="utf-8", errors="ignore")[:8192]
        except OSError:
            continue
        name = parse_header(text, "Theme Name")
        if not name:
            continue
        version = parse_header(text, "Version") or "unknown"
        themes.append(Theme(slug=child.name, name=name, version=version, path=child))
    return themes


def check_mu_plugins(root: Path) -> list[Finding]:
    # Must-use plugins are loaded automatically by WordPress from top-level PHP
    # files, so they are always inventory-relevant even without activation state.
    mu_plugins_dir = root / "wp-content" / "mu-plugins"
    if not mu_plugins_dir.exists():
        return [Finding("mu-plugins", "INFO", "No must-use plugin directory was detected.")]

    plugin_files = sorted(mu_plugins_dir.glob("*.php"))
    if not plugin_files:
        return [
            Finding(
                "mu-plugins",
                "INFO",
                "Must-use plugin directory exists but no top-level PHP mu-plugin files were detected.",
                path=str(mu_plugins_dir),
            )
        ]

    findings = [Finding("mu-plugins", "INFO", f"Detected {len(plugin_files)} must-use plugin file(s).")]
    for plugin_file in plugin_files:
        plugin = parse_plugin_file(plugin_file, plugin_file.stem)
        if plugin:
            message = f"{plugin.name} ({plugin.slug}) version {plugin.version}"
        else:
            message = f"{plugin_file.name} has no standard plugin header."
        findings.append(
            Finding(
                "mu-plugin-inventory",
                "INFO",
                message,
                "Must-use plugins load automatically and cannot be disabled from wp-admin.",
                path=str(plugin_file),
            )
        )
    nested_php = [path for path in mu_plugins_dir.glob("*/*.php")]
    if nested_php:
        findings.append(
            Finding(
                "mu-plugins",
                "INFO",
                f"Detected {len(nested_php)} nested PHP file(s) under mu-plugins.",
                "WordPress only auto-loads top-level mu-plugin files.",
                path=str(mu_plugins_dir),
            )
        )
    return findings


def check_cves(
    root: Path,
    core_version: str,
    plugins: list[Plugin],
    themes: list[Theme],
    cve_map_path: Path | None,
    cve_match: str,
    cve_max_results: int,
    cve_max_keyword_targets: int,
    cve_cache_path: Path | None,
    nvd_api_key: str,
    nvd_delay: float | None,
    timeout: float,
) -> list[Finding]:
    # Build NVD search targets from detected core/plugins/themes, then prefer
    # high-confidence CPE lookups and use keyword search only as a fallback.
    cve_map, map_findings = load_cve_map(cve_map_path)
    findings: list[Finding] = [
        Finding(
            "cve-search",
            "INFO",
            "NVD CVE search is enabled.",
            (
                "This product uses data from the NVD API but is not endorsed or certified by the NVD. "
                f"NVD_API_KEY configured: {'yes' if nvd_api_key else 'no'}."
            ),
            source="nvd",
        ),
        *map_findings,
    ]
    targets = build_cve_targets(root, core_version, plugins, themes)
    if not targets:
        findings.append(Finding("cve-search", "INFO", "No CVE search targets were detected.", source="nvd"))
        return findings

    cache = load_nvd_cache(cve_cache_path)
    delay = nvd_delay if nvd_delay is not None else (0.6 if nvd_api_key else 6.0)
    keyword_targets_used = 0
    request_count = 0
    match_count = 0
    transient_error_count = 0
    unmapped_targets: list[CveTarget] = []

    for target in targets:
        target_cpes = cpe_values_for_target(target, cve_map)
        if cve_match in {"cpe", "both"} and target_cpes:
            # CPE searches are considered higher confidence because NVD performs
            # product matching against structured platform identifiers.
            for cpe_name in target_cpes:
                request_count += 1
                payload, error, from_cache = fetch_nvd_cves(
                    {
                        "cpeName": cpe_name,
                        "isVulnerable": "",
                        "noRejected": "",
                        "resultsPerPage": str(cve_max_results),
                    },
                    nvd_api_key=nvd_api_key,
                    timeout=timeout,
                    cache=cache,
                    cache_path=cve_cache_path,
                )
                findings.extend(
                    nvd_payload_to_findings(
                        payload,
                        error,
                        target,
                        confidence="cpe",
                        query=cpe_name,
                        from_cache=from_cache,
                    )
                )
                if payload:
                    match_count += len(payload.get("vulnerabilities", []))
                transient_error_count = update_transient_error_count(transient_error_count, error)
                if transient_error_count >= 3:
                    findings.append(nvd_circuit_breaker_finding(transient_error_count))
                    return finalize_cve_findings(
                        findings,
                        request_count,
                        match_count,
                        keyword_targets_used,
                        cve_max_keyword_targets,
                        cve_match,
                        unmapped_targets,
                    )
                sleep_after_nvd_request(delay, from_cache)
            continue

        if cve_match in {"keyword", "both"} and target.kind != "core":
            # Keyword searches can be noisy, so they are capped and reported as
            # lower-confidence findings.
            if keyword_targets_used >= cve_max_keyword_targets:
                continue
            keyword_targets_used += 1
            keyword = cve_keyword_for_target(target)
            request_count += 1
            payload, error, from_cache = fetch_nvd_cves(
                {"keywordSearch": keyword, "noRejected": "", "resultsPerPage": str(cve_max_results)},
                nvd_api_key=nvd_api_key,
                timeout=timeout,
                cache=cache,
                cache_path=cve_cache_path,
            )
            findings.extend(
                nvd_payload_to_findings(
                    payload,
                    error,
                    target,
                    confidence="keyword",
                    query=keyword,
                    from_cache=from_cache,
                )
            )
            if payload:
                match_count += len(payload.get("vulnerabilities", []))
            transient_error_count = update_transient_error_count(transient_error_count, error)
            if transient_error_count >= 3:
                findings.append(nvd_circuit_breaker_finding(transient_error_count))
                return finalize_cve_findings(
                    findings,
                    request_count,
                    match_count,
                    keyword_targets_used,
                    cve_max_keyword_targets,
                    cve_match,
                    unmapped_targets,
                )
            sleep_after_nvd_request(delay, from_cache)
        elif cve_match == "cpe" and not target_cpes:
            unmapped_targets.append(target)

    return finalize_cve_findings(
        findings,
        request_count,
        match_count,
        keyword_targets_used,
        cve_max_keyword_targets,
        cve_match,
        unmapped_targets,
    )


def finalize_cve_findings(
    findings: list[Finding],
    request_count: int,
    match_count: int,
    keyword_targets_used: int,
    cve_max_keyword_targets: int,
    cve_match: str,
    unmapped_targets: list[CveTarget],
) -> list[Finding]:
    if cve_match == "cpe" and unmapped_targets:
        examples = ", ".join(f"{target.kind}:{target.slug}" for target in unmapped_targets[:10])
        if len(unmapped_targets) > 10:
            examples += ", ..."
        findings.append(
            Finding(
                "cve-search",
                "INFO",
                f"Skipped {len(unmapped_targets)} plugin/theme target(s) without CPE mappings.",
                f"examples: {examples}",
                remediation="Provide --cve-map or use --cve-match keyword/both for lower-confidence keyword searches.",
                source="nvd",
            )
        )
    if cve_match in {"keyword", "both"} and keyword_targets_used >= cve_max_keyword_targets:
        findings.append(
            Finding(
                "cve-search",
                "INFO",
                f"Keyword CVE search was limited to {cve_max_keyword_targets} plugin/theme target(s).",
                "Increase --cve-max-keyword-targets to search more targets.",
                source="nvd",
            )
        )
    findings.append(
        Finding(
            "cve-search",
            "INFO",
            f"NVD CVE search completed with {request_count} request(s) and {match_count} raw match(es).",
            source="nvd",
        )
        )
    return findings


def update_transient_error_count(current_count: int, error: str) -> int:
    if not error:
        return 0
    if is_transient_nvd_error(error):
        return current_count + 1
    return 0


def is_transient_nvd_error(error: str) -> bool:
    lowered = error.lower()
    return any(marker in lowered for marker in ("http 429", "http 503", "timed out", "temporarily unavailable"))


def nvd_circuit_breaker_finding(error_count: int) -> Finding:
    return Finding(
        "cve-search",
        "WARN",
        "Stopped NVD CVE search after repeated transient NVD failures.",
        f"consecutive transient failures: {error_count}",
        remediation=(
            "Retry later, configure NVD_API_KEY in .env, reduce targets with --cve-match cpe, "
            "or use --cve-cache to reuse prior responses."
        ),
        source="nvd",
    )


def build_cve_targets(root: Path, core_version: str, plugins: list[Plugin], themes: list[Theme]) -> list[CveTarget]:
    # Normalize core, plugins, and themes into one target type for the NVD lookup pipeline.
    targets: list[CveTarget] = []
    if core_version:
        targets.append(
            CveTarget(
                kind="core",
                slug="wordpress",
                name="WordPress",
                version=core_version,
                path=str(root / "wp-includes" / "version.php"),
            )
        )
    targets.extend(
        CveTarget(
            kind="plugin",
            slug=plugin.slug,
            name=plugin.name,
            version=plugin.version,
            path=str(plugin.path),
        )
        for plugin in plugins
    )
    targets.extend(
        CveTarget(
            kind="theme",
            slug=theme.slug,
            name=theme.name,
            version=theme.version,
            path=str(theme.path),
        )
        for theme in themes
    )
    return targets


def load_cve_map(path: Path | None) -> tuple[dict[str, Any], list[Finding]]:
    if path is None:
        return {}, [
            Finding(
                "cve-map",
                "INFO",
                "No CVE CPE map was supplied.",
                "WordPress core uses a built-in CPE template; plugins/themes use keyword fallback unless mapped.",
                source="nvd",
            )
        ]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [
            Finding(
                "cve-map",
                "WARN",
                "Could not read CVE CPE map.",
                str(exc),
                path=str(path),
                source="nvd",
            )
        ]
    if not isinstance(payload, dict):
        return {}, [
            Finding(
                "cve-map",
                "WARN",
                "CVE CPE map must be a JSON object.",
                path=str(path),
                source="nvd",
            )
        ]
    return payload, [Finding("cve-map", "PASS", "CVE CPE map was loaded.", path=str(path), source="nvd")]


def cpe_values_for_target(target: CveTarget, cve_map: dict[str, Any]) -> list[str]:
    # WordPress core has a built-in CPE template; plugins/themes require an
    # explicit map because their vendor/product names are not consistently derivable.
    if target.kind == "core":
        configured = cve_map.get("core")
        if configured:
            return normalize_cpe_map_value(configured, target)
        return [
            format_cpe_template(
                "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
                target,
            )
        ]

    collection = cve_map.get(f"{target.kind}s", {})
    if isinstance(collection, dict):
        value = collection.get(target.slug) or collection.get(target.name)
        if value:
            return normalize_cpe_map_value(value, target)
    return []


def normalize_cpe_map_value(value: Any, target: CveTarget) -> list[str]:
    values: list[str]
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [item for item in value if isinstance(item, str)]
    elif isinstance(value, dict):
        raw = value.get("cpe") or value.get("cpes") or value.get("template")
        values = normalize_cpe_map_value(raw, target) if raw else []
    else:
        values = []
    return [format_cpe_template(item, target) for item in values if item.strip()]


def format_cpe_template(template: str, target: CveTarget) -> str:
    return template.format(
        version=quote_cpe_component(target.version),
        slug=quote_cpe_component(target.slug),
        name=quote_cpe_component(slugify(target.name)),
    )


def quote_cpe_component(value: str) -> str:
    return (value or "*").strip().replace(" ", "_").lower()


def slugify(value: str) -> str:
    lowered = value.strip().lower()
    lowered = re.sub(r"[^a-z0-9._-]+", "_", lowered)
    return lowered.strip("_") or "*"


def cve_keyword_for_target(target: CveTarget) -> str:
    pieces = ["WordPress"]
    if target.name and target.name.lower() != target.slug.lower():
        pieces.append(target.name)
    pieces.append(target.slug)
    return " ".join(dict.fromkeys(piece.strip() for piece in pieces if piece.strip()))


def fetch_nvd_cves(
    params: dict[str, str],
    nvd_api_key: str,
    timeout: float,
    cache: dict[str, Any],
    cache_path: Path | None,
) -> tuple[dict[str, Any] | None, str, bool]:
    # Cache by fully built URL so identical parameter sets reuse the same NVD response.
    url = build_nvd_url(params)
    cache_key = url
    cached = cache.get("responses", {}).get(cache_key)
    if isinstance(cached, dict):
        return cached, "", True

    headers = {"User-Agent": f"ic-wp-hardening/{__version__}"}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = exc.headers.get("message") or exc.reason
        return None, f"NVD API HTTP {exc.code}: {message}", False
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return None, f"NVD API request failed: {exc}", False

    if not isinstance(payload, dict):
        return None, "NVD API returned an unexpected payload.", False
    if cache_path:
        cache.setdefault("responses", {})[cache_key] = payload
        write_nvd_cache(cache_path, cache)
    return payload, "", False


def build_nvd_url(params: dict[str, str]) -> str:
    # NVD accepts some flags as key-only query parameters; empty strings represent
    # those flags while normal values are URL encoded.
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    flags = [key for key, value in params.items() if value == ""]
    values = {key: value for key, value in params.items() if value != ""}
    query = urllib.parse.urlencode(values)
    if flags:
        query = "&".join(part for part in [query, *flags] if part)
    return f"{base}?{query}" if query else base


def load_nvd_cache(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"responses": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"responses": {}}
    if isinstance(payload, dict) and isinstance(payload.get("responses"), dict):
        return payload
    return {"responses": {}}


def write_nvd_cache(path: Path, cache: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sleep_after_nvd_request(delay: float, from_cache: bool) -> None:
    if not from_cache and delay > 0:
        time.sleep(delay)


def nvd_payload_to_findings(
    payload: dict[str, Any] | None,
    error: str,
    target: CveTarget,
    confidence: str,
    query: str,
    from_cache: bool,
) -> list[Finding]:
    # Convert raw NVD records into normal findings while keeping the raw summary
    # in evidence for machine-readable follow-up.
    if error:
        return [
            Finding(
                "cve-search",
                "WARN",
                f"Could not search NVD CVEs for {target.kind} {target.slug}.",
                error,
                path=target.path,
                source="nvd",
            )
        ]
    if payload is None:
        return []

    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return [
            Finding(
                "cve-search",
                "PASS" if confidence == "cpe" else "INFO",
                f"No NVD CVE matches found for {target.kind} {target.slug}.",
                f"confidence: {confidence}; query: {query}; cached: {from_cache}",
                path=target.path,
                source=f"nvd:{confidence}",
            )
        ]

    findings: list[Finding] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        summary = summarize_nvd_cve(cve)
        status = cve_finding_status(summary, confidence)
        confidence_label = "confirmed CPE match" if confidence == "cpe" else "potential keyword match"
        findings.append(
            Finding(
                "cve",
                status,
                f"{summary['id']} may affect {target.kind} {target.slug}.",
                (
                    f"severity: {summary['severity']}; score: {summary['score']}; "
                    f"confidence: {confidence_label}; published: {summary['published']}; "
                    f"kev: {summary['kev']}; cached: {from_cache}"
                ),
                path=target.path,
                remediation="Review the CVE references and update or mitigate if applicable.",
                evidence=json.dumps(
                    {
                        "target": asdict(target),
                        "query": query,
                        "confidence": confidence,
                        **summary,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                source=f"nvd:{confidence}",
            )
        )
    return findings


def summarize_nvd_cve(cve: dict[str, Any]) -> dict[str, Any]:
    # Keep only the report-relevant NVD fields and cap references to avoid huge reports.
    metrics = extract_nvd_cvss(cve.get("metrics", {}))
    references = extract_nvd_references(cve)
    return {
        "id": str(cve.get("id") or "CVE-UNKNOWN"),
        "status": str(cve.get("vulnStatus") or ""),
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "severity": metrics["severity"],
        "score": metrics["score"],
        "vector": metrics["vector"],
        "kev": bool(cve.get("cisaExploitAdd")),
        "description": first_english_description(cve.get("descriptions", [])),
        "references": references[:5],
    }


def extract_nvd_cvss(metrics: Any) -> dict[str, Any]:
    # Prefer newer CVSS versions first, falling back to older metrics when needed.
    if not isinstance(metrics, dict):
        return {"severity": "UNKNOWN", "score": "", "vector": ""}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not isinstance(values, list) or not values:
            continue
        metric = values[0]
        if not isinstance(metric, dict):
            continue
        cvss_data = metric.get("cvssData", {})
        if not isinstance(cvss_data, dict):
            continue
        severity = metric.get("cvssV2Severity") or cvss_data.get("baseSeverity") or "UNKNOWN"
        return {
            "severity": str(severity).upper(),
            "score": cvss_data.get("baseScore", ""),
            "vector": str(cvss_data.get("vectorString") or ""),
        }
    return {"severity": "UNKNOWN", "score": "", "vector": ""}


def extract_nvd_references(cve: dict[str, Any]) -> list[str]:
    references = cve.get("references", [])
    if isinstance(references, dict):
        references = references.get("referenceData", [])
    if not isinstance(references, list):
        return []
    urls: list[str] = []
    for ref in references:
        if isinstance(ref, dict):
            url = str(ref.get("url") or "").strip()
            if url:
                urls.append(url)
    return urls


def first_english_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""
    fallback = ""
    for description in descriptions:
        if not isinstance(description, dict):
            continue
        value = str(description.get("value") or "").strip()
        if not fallback:
            fallback = value
        if description.get("lang") == "en":
            return value
    return fallback


def cve_finding_status(summary: dict[str, Any], confidence: str) -> str:
    # Confirmed CPE matches are escalated by severity; keyword matches stay softer
    # because name-based matching can include unrelated products.
    severity = str(summary.get("severity", "")).upper()
    if summary.get("kev"):
        return "FAIL"
    if confidence == "keyword":
        return "WARN" if severity in {"CRITICAL", "HIGH"} else "INFO"
    if severity in {"CRITICAL", "HIGH"}:
        return "FAIL"
    if severity in {"MEDIUM", "LOW"}:
        return "WARN"
    return "INFO"


def check_wp_cli_checksums(
    root: Path,
    use_wp_cli: bool,
    wp_cli_bin: str,
    verify_checksums: str,
    timeout: float,
) -> list[Finding]:
    # Checksum verification is deliberately separate from normal inventory checks
    # because it requires WP-CLI and can perform network-backed package lookups.
    if verify_checksums == "none":
        return []
    if not use_wp_cli:
        return [
            Finding(
                "checksums",
                "WARN",
                "Checksum verification was requested but WP-CLI is not available.",
                remediation="Install WP-CLI or run with --use-wp-cli always --wp-cli-bin /path/to/wp.",
                source="wp-cli",
            )
        ]

    findings: list[Finding] = []
    if verify_checksums in {"core", "all"}:
        ok, output = run_wp_cli_plain(root, wp_cli_bin, ["core", "verify-checksums"], timeout)
        findings.append(
            Finding(
                "core-checksums",
                "PASS" if ok else "FAIL",
                "WordPress core checksum verification passed." if ok else "WordPress core checksum verification failed.",
                output,
                remediation="" if ok else "Review changed core files and restore from a trusted release.",
                source="wp-cli",
            )
        )
    if verify_checksums in {"plugins", "all"}:
        ok, output = run_wp_cli_plain(root, wp_cli_bin, ["plugin", "verify-checksums", "--all"], timeout)
        findings.append(
            Finding(
                "plugin-checksums",
                "PASS" if ok else "WARN",
                "Plugin checksum verification passed." if ok else "Plugin checksum verification reported issues.",
                output,
                remediation="" if ok else "Review modified plugin files and plugins not hosted on WordPress.org.",
                source="wp-cli",
            )
        )
    return findings


def check_exposed_files(
    scan_root: Path,
    max_findings: int,
    wp_root: Path | None = None,
) -> list[Finding]:
    # Detect files commonly left behind after installs, backups, debugging, or
    # manual maintenance. These can disclose versions, credentials, or database dumps.
    if not scan_root.exists():
        return [
            Finding(
                "exposed-files",
                "WARN",
                "Exposed-file scan root does not exist.",
                path=str(scan_root),
            )
        ]
    if not scan_root.is_dir():
        return [
            Finding(
                "exposed-files",
                "WARN",
                "Exposed-file scan root is not a directory.",
                path=str(scan_root),
            )
        ]

    findings: list[Finding] = []
    checked_files = 0
    reported = 0
    suppressed = 0

    for path in iter_scannable_files(scan_root):
        checked_files += 1
        finding = evaluate_exposed_file(path, scan_root)
        if finding:
            if reported < max_findings:
                findings.append(finding)
                reported += 1
            else:
                suppressed += 1

    summary = f"Checked {checked_files} file(s)."
    separate_root_detail = ""
    if wp_root is not None and scan_root != wp_root:
        separate_root_detail = f"DocumentRoot: {scan_root}\nWordPress root: {wp_root}"

    if not findings and suppressed == 0:
        return [
            Finding(
                "exposed-files",
                "PASS",
                "No exposed backup, dump, archive, or debug files were detected.",
                "\n".join(part for part in [summary, separate_root_detail] if part),
                path=str(scan_root),
            )
        ]

    findings.insert(
        0,
        Finding(
            "exposed-files",
            "WARN",
            "Potentially exposed files were detected.",
            summary,
            path=str(scan_root),
        ),
    )
    if suppressed:
        findings.append(
            Finding(
                "exposed-files",
                "WARN",
                f"Suppressed {suppressed} additional exposed-file finding(s).",
                f"Increase --max-file-scan-findings above {max_findings} to show more.",
            )
        )
    if separate_root_detail:
        findings.append(
            Finding(
                "exposed-files",
                "INFO",
                "Exposed-file scan used a separate DocumentRoot.",
                separate_root_detail,
                path=str(scan_root),
            )
        )
    return findings


def evaluate_exposed_file(path: Path, root: Path) -> Finding | None:
    rel = safe_relative(path, root)
    name = path.name.lower()
    rel_lower = rel.lower()

    if name == ".env" or name.startswith((".env.", ".env~")):
        return Finding(
            "exposed-files",
            "FAIL",
            f"Environment file is present under the document root: {rel}.",
            remediation="Move environment files outside the document root.",
            path=str(path),
        )

    vcs_metadata = {
        ".git/config": "Git metadata",
        ".svn/entries": "Subversion metadata",
        ".hg/hgrc": "Mercurial metadata",
    }
    for suffix, label in vcs_metadata.items():
        if rel_lower == suffix or rel_lower.endswith(f"/{suffix}"):
            return Finding(
                "exposed-files",
                "FAIL",
                f"{label} is present under the document root: {rel}.",
                remediation=(
                    "Remove VCS metadata from the document root or block direct "
                    "web access."
                ),
                path=str(path),
            )

    if name.startswith("wp-config.php") and name != "wp-config.php":
        return Finding(
            "exposed-files",
            "FAIL",
            f"wp-config.php backup or temporary file is present: {rel}.",
            remediation="Remove configuration backups from the document root.",
            path=str(path),
        )

    dump_suffixes = (".sql", ".sql.gz", ".sql.zip", ".sql.bz2", ".sql.xz")
    if rel_lower.endswith(dump_suffixes):
        return Finding(
            "exposed-files",
            "FAIL",
            f"Database dump file is present: {rel}.",
            remediation=(
                "Move database dumps outside the document root and rotate exposed "
                "credentials."
            ),
            path=str(path),
        )

    if name in {"debug.log", "error_log", "php_errorlog"}:
        return Finding(
            "exposed-files",
            "WARN",
            f"Debug or error log file is present: {rel}.",
            remediation="Move logs outside the document root or block direct web access.",
            path=str(path),
        )

    if name == "readme.html" or rel_lower == "install.php":
        return Finding(
            "exposed-files",
            "WARN",
            f"Public WordPress metadata or installer file is present: {rel}.",
            remediation="Remove public metadata/install files when they are not required.",
            path=str(path),
        )

    backup_suffixes = (".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~")
    if rel_lower.endswith(backup_suffixes):
        return Finding(
            "exposed-files",
            "WARN",
            f"Backup or temporary file is present: {rel}.",
            remediation="Remove backup and temporary files from the document root.",
            path=str(path),
        )

    archive_suffixes = (".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z")
    if rel_lower.endswith(archive_suffixes):
        return Finding(
            "exposed-files",
            "WARN",
            f"Archive file is present under the document root: {rel}.",
            remediation=(
                "Move archives outside the document root unless direct download is "
                "intentional."
            ),
            path=str(path),
        )

    return None


def check_uploads_php(root: Path, max_findings: int) -> list[Finding]:
    uploads_dir = root / "wp-content" / "uploads"
    if not uploads_dir.exists():
        return [Finding("uploads-php", "INFO", "No wp-content/uploads directory was detected.")]

    findings: list[Finding] = []
    checked_files = 0
    reported = 0
    suppressed = 0

    for path in iter_scannable_files(uploads_dir):
        checked_files += 1
        finding = evaluate_uploads_php_file(path, root)
        if finding:
            if reported < max_findings:
                findings.append(finding)
                reported += 1
            else:
                suppressed += 1

    summary = f"Checked {checked_files} upload file(s)."
    if not findings and suppressed == 0:
        return [
            Finding(
                "uploads-php",
                "PASS",
                "No PHP-capable files were detected in uploads.",
                summary,
            )
        ]

    findings.insert(
        0,
        Finding("uploads-php", "FAIL", "PHP-capable files were detected in uploads.", summary),
    )
    if suppressed:
        findings.append(
            Finding(
                "uploads-php",
                "WARN",
                f"Suppressed {suppressed} additional uploads PHP finding(s).",
                f"Increase --max-file-scan-findings above {max_findings} to show more.",
            )
        )
    return findings


def evaluate_uploads_php_file(path: Path, root: Path) -> Finding | None:
    rel = safe_relative(path, root)
    name = path.name.lower()
    executable_suffixes = (
        ".php",
        ".phtml",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".phps",
        ".pht",
        ".phar",
    )
    disguised_markers = (".php.", ".phtml.", ".pht.", ".phar.")

    if name.endswith(executable_suffixes):
        return Finding(
            "uploads-php",
            "FAIL",
            f"PHP-capable file is present in uploads: {rel}.",
            remediation="Remove the file and investigate how executable content reached uploads.",
            path=str(path),
        )

    if any(marker in name for marker in disguised_markers):
        return Finding(
            "uploads-php",
            "FAIL",
            f"Disguised PHP-like filename is present in uploads: {rel}.",
            remediation="Remove the file and investigate whether upload filtering was bypassed.",
            path=str(path),
        )

    if file_contains_php_tag(path):
        return Finding(
            "uploads-php",
            "FAIL",
            f"PHP code marker was found in an upload file: {rel}.",
            remediation="Remove the file and investigate possible webshell activity.",
            path=str(path),
        )

    return None


def file_contains_php_tag(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:8192]
    except OSError:
        return False
    lowered = sample.lower()
    return b"<?php" in lowered or b"<?=" in lowered


def iter_scannable_files(root: Path) -> Iterable[Path]:
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in {"node_modules", "vendor"}]
        current = Path(current_root)
        for name in sorted(files):
            yield current / name


def check_permissions(root: Path, max_findings: int) -> list[Finding]:
    # Walk the WordPress tree and report risky permission bits, limiting detailed
    # rows so a badly configured site does not produce an unreadable report.
    findings: list[Finding] = []
    checked_files = 0
    checked_dirs = 0
    reported = 0
    suppressed = 0

    for current_root, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in {".git", "node_modules", "vendor"}]
        current = Path(current_root)

        for name in dirs:
            path = current / name
            checked_dirs += 1
            finding = evaluate_permission(path, is_dir=True, root=root)
            if finding:
                if reported < max_findings:
                    findings.append(finding)
                    reported += 1
                else:
                    suppressed += 1

        for name in files:
            path = current / name
            checked_files += 1
            finding = evaluate_permission(path, is_dir=False, root=root)
            if finding:
                if reported < max_findings:
                    findings.append(finding)
                    reported += 1
                else:
                    suppressed += 1

    summary = f"Checked {checked_dirs} directorie(s) and {checked_files} file(s)."
    if not findings and suppressed == 0:
        return [Finding("file-permissions", "PASS", "No risky file permissions were detected.", summary)]

    findings.insert(0, Finding("file-permissions", "WARN", "Risky file permissions were detected.", summary))
    if suppressed:
        findings.append(
            Finding(
                "file-permissions",
                "WARN",
                f"Suppressed {suppressed} additional permission finding(s).",
                f"Increase --max-permission-findings above {max_findings} to show more.",
            )
        )
    return findings


def evaluate_permission(path: Path, is_dir: bool, root: Path) -> Finding | None:
    # Treat world-writable paths as failures, and flag common WordPress hardening
    # expectations for wp-config.php, directories, and regular files.
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        return Finding("file-permissions", "WARN", "Could not read file permissions.", str(exc), path=str(path))

    rel = safe_relative(path, root)
    if mode & 0o002:
        return Finding(
            "file-permissions",
            "FAIL",
            f"World-writable permission on {rel}.",
            f"mode: {mode:o}",
            path=str(path),
        )

    if rel == "wp-config.php" and mode & 0o137:
        return Finding(
            "file-permissions",
            "WARN",
            "wp-config.php is more permissive than 0640.",
            f"mode: {mode:o}",
            path=str(path),
        )

    if is_dir and mode & 0o022:
        return Finding(
            "file-permissions",
            "WARN",
            f"Directory is writable by group or others: {rel}.",
            f"mode: {mode:o}",
            path=str(path),
        )

    if not is_dir and mode & 0o133:
        return Finding(
            "file-permissions",
            "WARN",
            f"File is more permissive than 0644: {rel}.",
            f"mode: {mode:o}",
            path=str(path),
        )
    return None


def check_php_settings(php_ini: Path | None, php_bin: str) -> list[Finding]:
    # Read PHP settings from an explicit php.ini when provided; otherwise inspect
    # the active PHP binary and evaluate a small set of production hardening keys.
    try:
        settings = read_php_settings(php_ini, php_bin)
    except Exception as exc:  # noqa: BLE001 - this is a CLI report surface.
        return [
            Finding(
                "php-settings",
                "WARN",
                "Could not read PHP settings.",
                str(exc),
            )
        ]

    if not settings:
        return [Finding("php-settings", "WARN", "No PHP settings were found.")]

    checks = [
        ("display_errors", "Off", "FAIL", "display_errors should be Off in production."),
        ("expose_php", "Off", "WARN", "expose_php should be Off."),
        ("allow_url_include", "Off", "FAIL", "allow_url_include should be Off."),
        ("session.cookie_httponly", "On", "WARN", "session.cookie_httponly should be On."),
        ("session.cookie_secure", "On", "WARN", "session.cookie_secure should be On for HTTPS sites."),
    ]
    findings: list[Finding] = []
    for key, expected, bad_status, message in checks:
        actual = settings.get(key.lower())
        if actual is None:
            findings.append(Finding("php-settings", "INFO", f"{key} was not found."))
        elif normalize_php_bool(actual) == normalize_php_bool(expected):
            findings.append(Finding("php-settings", "PASS", f"{key} is {actual}."))
        else:
            findings.append(Finding("php-settings", bad_status, message, f"actual: {actual}"))

    disabled = settings.get("disable_functions", "")
    if not disabled or disabled.lower() in {"no value", "none"}:
        findings.append(
            Finding(
                "php-settings",
                "WARN",
                "disable_functions is empty.",
                "Consider disabling high-risk functions if the application does not require them.",
            )
        )
    else:
        findings.append(Finding("php-settings", "INFO", f"disable_functions: {disabled}"))

    if not settings.get("open_basedir") or settings.get("open_basedir", "").lower() in {"no value", "none"}:
        findings.append(
            Finding(
                "php-settings",
                "INFO",
                "open_basedir is not set.",
                "This may be acceptable depending on the hosting model.",
            )
        )
    else:
        findings.append(Finding("php-settings", "PASS", f"open_basedir is set: {settings['open_basedir']}"))

    return findings


def read_php_settings(php_ini: Path | None, php_bin: str) -> dict[str, str]:
    # Prefer a provided php.ini for deterministic scans; php -i is a fallback for
    # the runtime configuration on the current host.
    if php_ini:
        return parse_php_ini(php_ini.read_text(encoding="utf-8", errors="ignore"))

    completed = subprocess.run(
        [php_bin, "-i"],
        check=True,
        capture_output=True,
        text=True,
        timeout=8,
    )
    return parse_php_info(completed.stdout)


def parse_php_ini(text: str) -> dict[str, str]:
    # Parse simple php.ini key/value lines and ignore sections/comments.
    settings: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("["):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        settings[key.strip().lower()] = value.strip().strip('"').strip("'")
    return settings


def parse_php_info(text: str) -> dict[str, str]:
    # php -i emits "key => local => master" style rows; the first value is the local setting.
    settings: dict[str, str] = {}
    for raw_line in text.splitlines():
        if "=>" not in raw_line:
            continue
        parts = [part.strip() for part in raw_line.split("=>")]
        if len(parts) >= 2:
            settings[parts[0].lower()] = parts[1]
    return settings


def render_report(root: Path, findings: list[Finding], report_format: str) -> str:
    if report_format == "json":
        return render_json_report(root, findings)
    return render_markdown_report(root, findings)


def build_report_data(root: Path, findings: list[Finding]) -> dict[str, Any]:
    # Shared report payload used by both Markdown and JSON renderers.
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = {status: sum(1 for finding in findings if finding.status == status) for status in STATUSES}
    return {
        "generated": now,
        "tool": {"name": "ic-wp-hardening", "version": __version__},
        "target": str(root),
        "summary": counts,
        "findings": [asdict(finding) for finding in findings],
    }


def render_json_report(root: Path, findings: list[Finding]) -> str:
    return json.dumps(build_report_data(root, findings), ensure_ascii=False, indent=2) + "\n"


def render_markdown_report(root: Path, findings: list[Finding]) -> str:
    # Render findings as a Markdown table so reports are readable in terminals,
    # pull requests, and issue trackers.
    report = build_report_data(root, findings)
    counts = report["summary"]
    lines = [
        "# WordPress Hardening Report",
        "",
        f"- Generated: {report['generated']}",
        f"- Tool: ic-wp-hardening {__version__}",
        f"- Target: `{root}`",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in STATUSES:
        lines.append(f"| {status} | {counts[status]} |")

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Status | Check | Message | Detail | Remediation | Path | Source |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    md_escape(finding.status),
                    md_escape(finding.check),
                    md_escape(finding.message),
                    md_escape(finding.detail),
                    md_escape(finding.remediation),
                    md_escape(finding.path),
                    md_escape(finding.source),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def write_report(output: Path | None, report: str) -> None:
    if output:
        output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)


def exit_code(fail_on: str, findings: Iterable[Finding]) -> int:
    # Map the requested failure threshold to process status without changing the report contents.
    statuses = {finding.status for finding in findings}
    if fail_on == "never":
        return 0
    if fail_on == "warn" and ({"WARN", "FAIL"} & statuses):
        return 1
    if fail_on == "fail" and "FAIL" in statuses:
        return 1
    return 0


def normalize_severity(value: str) -> str:
    lowered = value.lower()
    if lowered in {"critical", "high", "fail", "failure"}:
        return "FAIL"
    if lowered in {"medium", "low", "warn", "warning"}:
        return "WARN"
    return "INFO"


def normalize_php_bool(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"1", "on", "true", "yes", "enabled"}:
        return "on"
    if lowered in {"0", "off", "false", "no", "disabled", "no value"}:
        return "off"
    return lowered


def compare_versions(left: str, right: str) -> int:
    left_key = version_key(left)
    right_key = version_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def version_key(value: str) -> tuple[list[int], str]:
    numeric = [int(part) for part in re.findall(r"\d+", value)]
    suffix = re.sub(r"[\d.\-_+ ]+", "", value).lower()
    return numeric, suffix


def version_matches(version: str, constraint: str) -> bool:
    # Support comma-separated constraints such as ">=1.0,<2.0" for local advisory matching.
    constraint = constraint.strip()
    if constraint in {"", "*"}:
        return True
    parts = [part.strip() for part in constraint.split(",") if part.strip()]
    return all(single_version_match(version, part) for part in parts)


def single_version_match(version: str, constraint: str) -> bool:
    match = re.match(r"^(<=|>=|<|>|=|==)?\s*(.+)$", constraint)
    if not match:
        return False
    operator = match.group(1) or "=="
    target = match.group(2).strip()
    comparison = compare_versions(version, target)
    return {
        "<": comparison < 0,
        "<=": comparison <= 0,
        ">": comparison > 0,
        ">=": comparison >= 0,
        "=": comparison == 0,
        "==": comparison == 0,
    }[operator]


def md_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def safe_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
