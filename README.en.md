# ic-wp-hardening

A CLI tool that checks WordPress version, plugins, file permissions, and PHP settings, then outputs a Markdown or JSON report.

The target is a local WordPress installation on the same server. The tool runs with the Python standard library only.

## Usage

```bash
python -m ic_wp_hardening /path/to/wordpress -o report.md
```

To install and use it as a command:

```bash
pip install .
ic-wp-hardening /path/to/wordpress -o report.md
```

To check for updates:

```bash
ic-wp-hardening /path/to/wordpress --online -o report.md
```

To output a JSON report:

```bash
ic-wp-hardening /path/to/wordpress --format json -o report.json
```

To specify a PHP configuration file:

```bash
ic-wp-hardening /path/to/wordpress --php-ini /etc/php.ini -o report.md
```

To explicitly use WP-CLI:

```bash
ic-wp-hardening /path/to/wordpress --use-wp-cli always --wp-cli-bin /usr/local/bin/wp -o report.md
```

When WP-CLI is available, the tool can inspect plugin and theme activation state, update state, and `wp-config.php` readability more accurately. The default is `--use-wp-cli auto`; if WP-CLI is not found, the tool falls back to static analysis.

## Checks

- WordPress root structure detection
- WordPress core version detection
- WordPress core update check when `--online` is specified
- Installed plugin detection
- wordpress.org plugin update checks when `--online` is specified
- Plugin vulnerability matching with a local JSON database
- Theme detection, and activation/update state when WP-CLI is available
- Must-use plugin (`wp-content/mu-plugins`) detection
- Key `wp-config.php` hardening settings
- File, directory, and `wp-config.php` permission checks
- PHP setting checks from `php.ini` or `php -i`

## WP-CLI Integration

WP-CLI is optional and is not added as a dependency.

```bash
ic-wp-hardening /path/to/wordpress --use-wp-cli auto
ic-wp-hardening /path/to/wordpress --use-wp-cli never
ic-wp-hardening /path/to/wordpress --use-wp-cli always --wp-cli-bin /path/to/wp
```

Main information added by WP-CLI integration:

- Plugin activation state, auto-update state, and update availability from `wp plugin list --format=json`
- Theme activation state, auto-update state, and update availability from `wp theme list --format=json`
- `wp-config.php` read verification from `wp config list --format=json`

Checksum verification can require network access, so it only runs when explicitly requested.

```bash
ic-wp-hardening /path/to/wordpress --verify-checksums core
ic-wp-hardening /path/to/wordpress --verify-checksums plugins
ic-wp-hardening /path/to/wordpress --verify-checksums all
```

## Report Formats

Markdown and JSON are supported.

```bash
ic-wp-hardening /path/to/wordpress --format markdown -o report.md
ic-wp-hardening /path/to/wordpress --format json -o report.json
```

The JSON report contains `summary` and `findings`. Each finding includes `check`, `status`, `message`, `detail`, `path`, `remediation`, `evidence`, and `source`.

## Plugin Vulnerability Database

To avoid depending on an external service API key, vulnerability data can be supplied as a local JSON file.

```bash
ic-wp-hardening /path/to/wordpress --vuln-db vuln-db.json -o report.md
```

Format:

```json
[
  {
    "slug": "example-plugin",
    "title": "Stored XSS in admin screen",
    "affected": "< 1.2.3",
    "fixed_in": "1.2.3",
    "severity": "high",
    "url": "https://example.com/advisory"
  }
]
```

`affected` can be specified as `*`, `< 1.2.3`, `<= 2.0.0`, or `>= 1.0.0, < 1.1.0`.

`severity` values of `critical` or `high` are treated as `FAIL`; `medium` or `low` are treated as `WARN`; all other values are treated as `INFO`.

## Exit Codes

By default, the command exits with status code `1` when any `FAIL` finding exists.

```bash
ic-wp-hardening /path/to/wordpress --fail-on warn
ic-wp-hardening /path/to/wordpress --fail-on never
```

## Notes

This tool is intended as an initial operational check. Plugin vulnerabilities are detected only when they are included in the supplied local database.
For comprehensive vulnerability assessment, combine this tool with current vulnerability feeds or commercial/public APIs.

## License

MIT

## Authors

- Info Circus,Inc (https://www.infocircus.jp/)
- incmplt (https://www.incmplt.net/)
