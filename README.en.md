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

When the WordPress root and the web server DocumentRoot are different:

```bash
ic-wp-hardening /var/www/html/wp --document-root /var/www/html -o report.md
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
- CVE search through the NVD API when explicitly enabled
- Theme detection, and activation/update state when WP-CLI is available
- Must-use plugin (`wp-content/mu-plugins`) detection
- Key `wp-config.php` hardening settings
- Detection of exposed backups, database dumps, archives, and debug logs
- Detection of PHP-capable or disguised PHP files under `wp-content/uploads`
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

## CVE Search

When `--cve-check` is specified, the tool searches the NVD API for CVEs related to WordPress core, plugins, and themes.

Do not put the NVD API key on the command line. Set it through an environment variable or `.env`.

```dotenv
NVD_API_KEY=your-api-key
```

`.env` can be placed in the current working directory or the target WordPress root. To use another file, set the `IC_WP_HARDENING_ENV_FILE` environment variable instead of passing a command-line argument.

```bash
ic-wp-hardening /path/to/wordpress --cve-check -o report.md
```

Search strategies:

```bash
ic-wp-hardening /path/to/wordpress --cve-check --cve-match cpe
ic-wp-hardening /path/to/wordpress --cve-check --cve-match keyword
ic-wp-hardening /path/to/wordpress --cve-check --cve-match both
```

The default is `cpe`. `cpe` is a higher-confidence search based on CPE names. WordPress core uses a built-in CPE template. Plugins and themes do not always have stable CPE coverage, so you can provide mappings with `--cve-map`.

```bash
ic-wp-hardening /path/to/wordpress --cve-check --cve-map cve-map.json
```

Example `cve-map.json`:

```json
{
  "plugins": {
    "example-plugin": "cpe:2.3:a:example:example_plugin:{version}:*:*:*:*:wordpress:*:*"
  },
  "themes": {
    "example-theme": "cpe:2.3:a:example:example_theme:{version}:*:*:*:*:wordpress:*:*"
  }
}
```

`keyword` searches use terms such as `WordPress <plugin name> <slug>`. Because keyword search can produce false positives or miss records, these results are reported as potential matches. It also increases NVD request volume, so use `--cve-match keyword` or `--cve-match both` only when needed.

To cache NVD API responses:

```bash
ic-wp-hardening /path/to/wordpress --cve-check --cve-cache .cache/nvd-cves.json
```

To respect NVD API rate limits, the default delay is 0.6 seconds with an API key and 6 seconds without an API key. Use `--nvd-delay` to override this.

## Report Formats

Markdown and JSON are supported.

```bash
ic-wp-hardening /path/to/wordpress --format markdown -o report.md
ic-wp-hardening /path/to/wordpress --format json -o report.json
```

The JSON report contains `summary` and `findings`. Each finding includes `check`, `status`, `message`, `detail`, `path`, `remediation`, `evidence`, and `source`.

To increase the number of reported file-scan findings:

```bash
ic-wp-hardening /path/to/wordpress --max-file-scan-findings 50 -o report.md
```

## DocumentRoot Dangerous File Detection

If WordPress is installed below the DocumentRoot, such as `/var/www/html/wp/`, pass `--document-root` to scan the whole DocumentRoot for dangerous files.

```bash
ic-wp-hardening /var/www/html/wp --document-root /var/www/html -o report.md
```

Examples:

- `.env`
- `.git/config`
- `wp-config.php~`
- `readme.html`
- `debug.log`
- `*.sql`
- `*.zip`

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

When using the NVD API, this product uses data from the NVD API but is not endorsed or certified by the NVD. CVE keyword search is supplemental; review CVE references, CPE data, affected versions, and fixed versions before making a final assessment.

## License

MIT

## Authors

- Info Circus,Inc (https://www.infocircus.jp/)
- incmplt (https://www.incmplt.net/)
