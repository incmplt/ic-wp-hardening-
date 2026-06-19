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
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from . import __version__


STATUSES = ("PASS", "INFO", "WARN", "FAIL")


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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.wp_root.resolve()

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
    findings.extend(check_mu_plugins(root))
    findings.extend(
        check_wp_cli_checksums(
            root,
            use_wp_cli,
            args.wp_cli_bin,
            args.verify_checksums,
            args.timeout,
        )
    )
    findings.extend(check_permissions(root, args.max_permission_findings))
    findings.extend(check_php_settings(args.php_ini, args.php_bin))

    report = render_report(root, findings, args.format)
    write_report(args.output, report)
    return exit_code(args.fail_on, findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ic-wp-hardening",
        description="Check a local WordPress installation and output a security report.",
    )
    parser.add_argument("wp_root", type=Path, help="Path to the WordPress document root.")
    parser.add_argument("-o", "--output", type=Path, help="Write report to this file.")
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
        "--max-permission-findings",
        type=int,
        default=25,
        help="Maximum individual permission paths shown in the report. Default: 25.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("fail", "warn", "never"),
        default="fail",
        help="Exit non-zero when findings reach this level. Default: fail.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def resolve_wp_cli(mode: str, wp_cli_bin: str) -> tuple[bool, list[Finding]]:
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
    with urllib.request.urlopen("https://api.wordpress.org/core/version-check/1.7/", timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    offers = payload.get("offers") or []
    versions = [offer.get("current") for offer in offers if offer.get("response") in {"upgrade", "latest"}]
    versions = [version for version in versions if isinstance(version, str)]
    if not versions:
        return ""
    return sorted(versions, key=version_key)[-1]


def check_wp_config(root: Path, use_wp_cli: bool, wp_cli_bin: str, timeout: float) -> list[Finding]:
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

    force_ssl_admin = values.get("FORCE_SSL_ADMIN")
    if force_ssl_admin is None:
        findings.append(Finding("wp-config", "INFO", "FORCE_SSL_ADMIN is not defined.", path=str(config_path)))
    elif normalize_php_bool(force_ssl_admin) == "on":
        findings.append(Finding("wp-config", "PASS", "FORCE_SSL_ADMIN is enabled.", path=str(config_path)))
    else:
        findings.append(Finding("wp-config", "WARN", "FORCE_SSL_ADMIN is disabled.", path=str(config_path)))

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


def check_wp_cli_checksums(
    root: Path,
    use_wp_cli: bool,
    wp_cli_bin: str,
    verify_checksums: str,
    timeout: float,
) -> list[Finding]:
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


def check_permissions(root: Path, max_findings: int) -> list[Finding]:
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
