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


if __name__ == "__main__":
    unittest.main()
