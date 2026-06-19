from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from ic_wp_hardening import cli


class CliTests(unittest.TestCase):
    def test_json_report_includes_static_wp_config_theme_and_mu_plugin_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_wordpress_fixture(Path(tmp))

            output = run_cli_capture(
                [
                    str(root),
                    "--format",
                    "json",
                    "--use-wp-cli",
                    "never",
                    "--php-ini",
                    str(root / "php.ini"),
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        checks = {finding["check"] for finding in report["findings"]}
        self.assertEqual(report["tool"]["name"], "ic-wp-hardening")
        self.assertIn("wp-config", checks)
        self.assertIn("themes", checks)
        self.assertIn("theme-inventory", checks)
        self.assertIn("mu-plugins", checks)
        self.assertIn("mu-plugin-inventory", checks)

    def test_wp_cli_adapter_reads_plugin_theme_and_config_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_wordpress_fixture(Path(tmp))
            fake_wp = make_fake_wp_cli(Path(tmp) / "wp")

            output = run_cli_capture(
                [
                    str(root),
                    "--format",
                    "json",
                    "--use-wp-cli",
                    "always",
                    "--wp-cli-bin",
                    str(fake_wp),
                    "--php-ini",
                    str(root / "php.ini"),
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        findings = report["findings"]
        self.assertTrue(any(f["check"] == "wp-cli" and f["status"] == "PASS" for f in findings))
        self.assertTrue(
            any(f["check"] == "plugin-update" and f["status"] == "WARN" for f in findings)
        )
        self.assertTrue(any(f["check"] == "themes" and f["status"] == "WARN" for f in findings))
        self.assertTrue(
            any(f["check"] == "wp-config" and f["source"] == "wp-cli" for f in findings)
        )

    def test_reports_exposed_files_uploads_php_and_additional_wp_config_risks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_wordpress_fixture(Path(tmp))
            uploads = root / "wp-content" / "uploads" / "2026" / "06"
            uploads.mkdir(parents=True)
            (root / "readme.html").write_text("WordPress readme\n", encoding="utf-8")
            (root / "backup.sql").write_text("-- dump\n", encoding="utf-8")
            (root / "wp-config.php~").write_text("backup\n", encoding="utf-8")
            (root / "wp-content" / "debug.log").write_text("debug\n", encoding="utf-8")
            (uploads / "shell.php").write_text("<?php echo 'owned';\n", encoding="utf-8")
            (uploads / "avatar.php.jpg").write_text("GIF89a\n", encoding="utf-8")
            config_path = root / "wp-config.php"
            config_path.write_text(
                config_path.read_text(encoding="utf-8")
                + "define('DISALLOW_FILE_MODS', false);\n"
                + "define('WP_DEBUG_LOG', true);\n"
                + "define('SCRIPT_DEBUG', true);\n"
                + "define('AUTOMATIC_UPDATER_DISABLED', true);\n"
                + "define('WP_AUTO_UPDATE_CORE', false);\n"
                + "define('WP_ENVIRONMENT_TYPE', 'development');\n",
                encoding="utf-8",
            )

            output = run_cli_capture(
                [
                    str(root),
                    "--format",
                    "json",
                    "--use-wp-cli",
                    "never",
                    "--php-ini",
                    str(root / "php.ini"),
                    "--fail-on",
                    "never",
                ]
            )

        report = json.loads(output)
        findings = report["findings"]
        self.assertTrue(
            any(
                f["check"] == "exposed-files"
                and f["status"] == "FAIL"
                and "backup.sql" in f["message"]
                for f in findings
            )
        )
        self.assertTrue(
            any(
                f["check"] == "exposed-files"
                and f["status"] == "FAIL"
                and "wp-config.php~" in f["message"]
                for f in findings
            )
        )
        self.assertTrue(
            any(
                f["check"] == "exposed-files"
                and f["status"] == "WARN"
                and "debug.log" in f["message"]
                for f in findings
            )
        )
        self.assertTrue(
            any(
                f["check"] == "uploads-php"
                and f["status"] == "FAIL"
                and "shell.php" in f["message"]
                for f in findings
            )
        )
        self.assertTrue(
            any(
                f["check"] == "uploads-php"
                and f["status"] == "FAIL"
                and "avatar.php.jpg" in f["message"]
                for f in findings
            )
        )
        self.assertTrue(
            any(
                f["check"] == "wp-config"
                and f["status"] == "WARN"
                and "DISALLOW_FILE_MODS is disabled" in f["message"]
                for f in findings
            )
        )
        self.assertTrue(
            any(
                f["check"] == "wp-config"
                and f["status"] == "WARN"
                and "WP_ENVIRONMENT_TYPE is development" in f["message"]
                for f in findings
            )
        )

    def test_cve_check_uses_nvd_client_and_reports_cpe_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_wordpress_fixture(Path(tmp))
            env_file = root / ".env"
            env_file.write_text("NVD_API_KEY=test-nvd-key\n", encoding="utf-8")
            cve_map = Path(tmp) / "cve-map.json"
            cve_map.write_text(
                json.dumps(
                    {
                        "plugins": {
                            "example-plugin": (
                                "cpe:2.3:a:example:example_plugin:{version}:*:*:*:*:wordpress:*:*"
                            )
                        }
                    }
                ),
                encoding="utf-8",
            )
            calls: list[dict[str, str]] = []
            api_keys: list[str] = []
            original_fetch = cli.fetch_nvd_cves
            original_api_key = os.environ.pop("NVD_API_KEY", None)
            original_env_file = os.environ.get("IC_WP_HARDENING_ENV_FILE")
            os.environ["IC_WP_HARDENING_ENV_FILE"] = str(env_file)

            def fake_fetch(
                params: dict[str, str],
                nvd_api_key: str,
                timeout: float,
                cache: dict[str, object],
                cache_path: Path | None,
            ) -> tuple[dict[str, object], str, bool]:
                calls.append(params)
                api_keys.append(nvd_api_key)
                if "example_plugin" in params.get("cpeName", ""):
                    return make_nvd_response(), "", False
                return {"vulnerabilities": []}, "", False

            cli.fetch_nvd_cves = fake_fetch
            try:
                output = run_cli_capture(
                    [
                        str(root),
                        "--format",
                        "json",
                        "--use-wp-cli",
                        "never",
                        "--php-ini",
                        str(root / "php.ini"),
                        "--cve-check",
                        "--cve-map",
                        str(cve_map),
                        "--nvd-delay",
                        "0",
                        "--fail-on",
                        "never",
                    ]
                )
            finally:
                cli.fetch_nvd_cves = original_fetch
                if original_api_key is None:
                    os.environ.pop("NVD_API_KEY", None)
                else:
                    os.environ["NVD_API_KEY"] = original_api_key
                if original_env_file is None:
                    os.environ.pop("IC_WP_HARDENING_ENV_FILE", None)
                else:
                    os.environ["IC_WP_HARDENING_ENV_FILE"] = original_env_file

        report = json.loads(output)
        findings = report["findings"]
        cve_findings = [finding for finding in findings if finding["check"] == "cve"]
        self.assertTrue(any("cpeName" in call for call in calls))
        self.assertFalse(any("keywordSearch" in call for call in calls))
        self.assertIn("test-nvd-key", api_keys)
        self.assertEqual(cve_findings[0]["source"], "nvd:cpe")
        self.assertIn("CVE-2024-0001", cve_findings[0]["message"])
        evidence = json.loads(cve_findings[0]["evidence"])
        self.assertEqual(evidence["id"], "CVE-2024-0001")
        self.assertEqual(evidence["target"]["slug"], "example-plugin")

    def test_cve_check_stops_after_repeated_transient_nvd_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_wordpress_fixture(Path(tmp))
            cve_map = Path(tmp) / "cve-map.json"
            cve_map.write_text(
                json.dumps(
                    {
                        "plugins": {
                            "example-plugin": (
                                "cpe:2.3:a:example:example_plugin:{version}:*:*:*:*:wordpress:*:*"
                            )
                        },
                        "themes": {
                            "example-theme": (
                                "cpe:2.3:a:example:example_theme:{version}:*:*:*:*:wordpress:*:*"
                            )
                        },
                    }
                ),
                encoding="utf-8",
            )
            calls: list[dict[str, str]] = []
            original_fetch = cli.fetch_nvd_cves

            def fake_fetch(
                params: dict[str, str],
                nvd_api_key: str,
                timeout: float,
                cache: dict[str, object],
                cache_path: Path | None,
            ) -> tuple[None, str, bool]:
                calls.append(params)
                return None, "NVD API HTTP 503: Service Unavailable", False

            cli.fetch_nvd_cves = fake_fetch
            try:
                output = run_cli_capture(
                    [
                        str(root),
                        "--format",
                        "json",
                        "--use-wp-cli",
                        "never",
                        "--php-ini",
                        str(root / "php.ini"),
                        "--cve-check",
                        "--cve-map",
                        str(cve_map),
                        "--nvd-delay",
                        "0",
                        "--fail-on",
                        "never",
                    ]
                )
            finally:
                cli.fetch_nvd_cves = original_fetch

        report = json.loads(output)
        findings = report["findings"]
        self.assertEqual(len(calls), 3)
        self.assertTrue(
            any(
                finding["check"] == "cve-search"
                and "Stopped NVD CVE search" in finding["message"]
                for finding in findings
            )
        )


def run_cli_capture(argv: list[str]) -> str:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = cli.main(argv)
    if exit_code not in {0, 1}:
        raise AssertionError(f"unexpected exit code: {exit_code}")
    return stdout.getvalue()


def make_wordpress_fixture(base: Path) -> Path:
    root = base / "site"
    (root / "wp-includes").mkdir(parents=True)
    (root / "wp-admin").mkdir()
    (root / "wp-content" / "plugins" / "example-plugin").mkdir(parents=True)
    (root / "wp-content" / "themes" / "example-theme").mkdir(parents=True)
    (root / "wp-content" / "mu-plugins").mkdir(parents=True)
    (root / "wp-includes" / "version.php").write_text("<?php\n$wp_version = '6.4.0';\n", encoding="utf-8")
    (root / "wp-content" / "plugins" / "example-plugin" / "example-plugin.php").write_text(
        "<?php\n/*\nPlugin Name: Example Plugin\nVersion: 1.0.0\n*/\n",
        encoding="utf-8",
    )
    (root / "wp-content" / "themes" / "example-theme" / "style.css").write_text(
        "/*\nTheme Name: Example Theme\nVersion: 1.0.0\n*/\n",
        encoding="utf-8",
    )
    (root / "wp-content" / "mu-plugins" / "loader.php").write_text(
        "<?php\n/*\nPlugin Name: Must Use Loader\nVersion: 0.1.0\n*/\n",
        encoding="utf-8",
    )
    salts = "\n".join(
        f"define('{key}', 'abcdefghijklmnopqrstuvwxyz0123456789{key.lower()}');"
        for key in [
            "AUTH_KEY",
            "SECURE_AUTH_KEY",
            "LOGGED_IN_KEY",
            "NONCE_KEY",
            "AUTH_SALT",
            "SECURE_AUTH_SALT",
            "LOGGED_IN_SALT",
            "NONCE_SALT",
        ]
    )
    (root / "wp-config.php").write_text(
        "<?php\n"
        "define('DISALLOW_FILE_EDIT', true);\n"
        "define('WP_DEBUG', false);\n"
        "define('FORCE_SSL_ADMIN', true);\n"
        "define('DB_PASSWORD', 'secret');\n"
        "$table_prefix = 'ic_';\n"
        f"{salts}\n",
        encoding="utf-8",
    )
    (root / "php.ini").write_text(
        "display_errors = Off\n"
        "expose_php = Off\n"
        "allow_url_include = Off\n"
        "session.cookie_httponly = On\n"
        "session.cookie_secure = On\n"
        "disable_functions = exec,passthru,shell_exec,system\n"
        "open_basedir = /tmp\n",
        encoding="utf-8",
    )
    return root


def make_fake_wp_cli(path: Path) -> Path:
    path.write_text(
        f"#!{sys.executable}\n"
        "import json\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if 'plugin' in args and 'list' in args:\n"
        "    print(json.dumps([{\n"
        "        'name': 'example-plugin', 'status': 'active', 'update': 'available',\n"
        "        'version': '1.0.0', 'update_version': '1.2.0', 'auto_update': 'off',\n"
        "        'file': 'example-plugin/example-plugin.php', 'title': 'Example Plugin',\n"
        "        'wporg_status': 'active', 'wporg_last_updated': '2026-01-01'\n"
        "    }]))\n"
        "elif 'theme' in args and 'list' in args:\n"
        "    print(json.dumps([\n"
        "        {'name': 'example-theme', 'status': 'active', 'update': 'none',\n"
        "         'version': '1.0.0', 'update_version': '', 'auto_update': 'off',\n"
        "         'title': 'Example Theme'},\n"
        "        {'name': 'old-theme', 'status': 'inactive', 'update': 'none',\n"
        "         'version': '0.1.0', 'update_version': '', 'auto_update': 'off',\n"
        "         'title': 'Old Theme'}\n"
        "    ]))\n"
        "elif 'config' in args and 'list' in args:\n"
        "    print(json.dumps([{'key': 'DISALLOW_FILE_EDIT', 'value': 'true', 'type': 'constant'}]))\n"
        "else:\n"
        "    print('unsupported fake wp command', args, file=sys.stderr)\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o755)
    return path


def make_nvd_response() -> dict[str, object]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "vulnStatus": "Analyzed",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Example Plugin for WordPress has a test vulnerability.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseSeverity": "HIGH",
                                    "baseScore": 8.1,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://example.test/CVE-2024-0001"}],
                }
            }
        ]
    }


if __name__ == "__main__":
    unittest.main()
