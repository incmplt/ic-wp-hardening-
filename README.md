# ic-wp-hardening

WordPress のバージョン、プラグイン、ファイルパーミッション、PHP 設定をまとめて確認し、Markdown レポートを出力する CLI ツールです。

対象は同じサーバー上にあるローカルの WordPress ルートです。Python 標準ライブラリのみで動きます。

## 使い方

```bash
python -m ic_wp_hardening /path/to/wordpress -o report.md
```

インストールしてコマンドとして使う場合:

```bash
pip install .
ic-wp-hardening /path/to/wordpress -o report.md
```

更新確認も行う場合:

```bash
ic-wp-hardening /path/to/wordpress --online -o report.md
```

JSON レポートを出力する場合:

```bash
ic-wp-hardening /path/to/wordpress --format json -o report.json
```

PHP 設定ファイルを明示する場合:

```bash
ic-wp-hardening /path/to/wordpress --php-ini /etc/php.ini -o report.md
```

WP-CLI を明示的に使う場合:

```bash
ic-wp-hardening /path/to/wordpress --use-wp-cli always --wp-cli-bin /usr/local/bin/wp -o report.md
```

WP-CLI が利用できる環境では、プラグインやテーマの有効状態、更新状態、`wp-config.php` の読み取り確認をより正確に行います。デフォルトは `--use-wp-cli auto` で、WP-CLI が見つからない場合は静的解析にフォールバックします。

## チェック項目

- WordPress ルート構造の確認
- WordPress コアバージョンの読み取り
- `--online` 指定時の WordPress コア更新確認
- インストール済みプラグインの検出
- `--online` 指定時の wordpress.org プラグイン更新確認
- ローカル JSON DB によるプラグイン脆弱性マッチング
- NVD API による CVE 検索（明示指定時のみ）
- テーマの検出、WP-CLI 利用時の有効/無効状態と更新確認
- must-use plugin (`wp-content/mu-plugins`) の検出
- `wp-config.php` の主要ハードニング設定確認
- ファイル、ディレクトリ、`wp-config.php` のパーミッション検査
- `php.ini` または `php -i` による PHP 設定確認

## WP-CLI 連携

WP-CLI は任意です。依存関係としては追加しません。

```bash
ic-wp-hardening /path/to/wordpress --use-wp-cli auto
ic-wp-hardening /path/to/wordpress --use-wp-cli never
ic-wp-hardening /path/to/wordpress --use-wp-cli always --wp-cli-bin /path/to/wp
```

WP-CLI 連携で追加される主な情報:

- `wp plugin list --format=json` によるプラグインの有効状態、自動更新、更新有無
- `wp theme list --format=json` によるテーマの有効状態、自動更新、更新有無
- `wp config list --format=json` による `wp-config.php` 読み取り確認

チェックサム検証はネットワークアクセスを伴うため、明示指定時のみ実行します。

```bash
ic-wp-hardening /path/to/wordpress --verify-checksums core
ic-wp-hardening /path/to/wordpress --verify-checksums plugins
ic-wp-hardening /path/to/wordpress --verify-checksums all
```

## CVE 検索

`--cve-check` を指定すると、NVD API で WordPress core、プラグイン、テーマに関係する CVE を検索します。

NVD API キーはコマンドラインに書かず、環境変数または `.env` に設定します。

```dotenv
NVD_API_KEY=your-api-key
```

`.env` はカレントディレクトリまたは対象 WordPress ルートに置けます。別のファイルを使う場合は、コマンドライン引数ではなく `IC_WP_HARDENING_ENV_FILE` 環境変数で指定します。

```bash
ic-wp-hardening /path/to/wordpress --cve-check -o report.md
```

検索方法:

```bash
ic-wp-hardening /path/to/wordpress --cve-check --cve-match cpe
ic-wp-hardening /path/to/wordpress --cve-check --cve-match keyword
ic-wp-hardening /path/to/wordpress --cve-check --cve-match both
```

デフォルトは `cpe` です。`cpe` は CPE による高信頼の検索です。WordPress core は組み込みの CPE テンプレートを使います。プラグインやテーマは CPE が安定して付いていないことがあるため、必要に応じて `--cve-map` で対応表を渡します。

```bash
ic-wp-hardening /path/to/wordpress --cve-check --cve-map cve-map.json
```

`cve-map.json` の例:

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

`keyword` は `WordPress <plugin name> <slug>` のようなキーワード検索です。誤検知や見逃しがあり得るため、レポートでは potential match として扱います。NVD へのリクエスト数も増えるため、必要な場合だけ `--cve-match keyword` または `--cve-match both` を指定してください。

NVD API のレスポンスをキャッシュする場合:

```bash
ic-wp-hardening /path/to/wordpress --cve-check --cve-cache .cache/nvd-cves.json
```

NVD API のレート制限に配慮するため、API キーありではデフォルト 0.6 秒、API キーなしではデフォルト 6 秒の待機を入れます。変更する場合は `--nvd-delay` を指定します。

## レポート形式

Markdown と JSON を選べます。

```bash
ic-wp-hardening /path/to/wordpress --format markdown -o report.md
ic-wp-hardening /path/to/wordpress --format json -o report.json
```

JSON には `summary` と `findings` が含まれます。各 finding には `check`, `status`, `message`, `detail`, `path`, `remediation`, `evidence`, `source` が入ります。

## プラグイン脆弱性 DB

外部サービスの API キーに依存しないよう、脆弱性情報は任意のローカル JSON ファイルとして渡します。

```bash
ic-wp-hardening /path/to/wordpress --vuln-db vuln-db.json -o report.md
```

形式:

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

`affected` は `*`, `< 1.2.3`, `<= 2.0.0`, `>= 1.0.0, < 1.1.0` のように指定できます。

`severity` は `critical`/`high` を `FAIL`、`medium`/`low` を `WARN`、その他を `INFO` として扱います。

## 終了コード

デフォルトでは `FAIL` がある場合に終了コード `1` を返します。

```bash
ic-wp-hardening /path/to/wordpress --fail-on warn
ic-wp-hardening /path/to/wordpress --fail-on never
```

## 注意点

このツールは運用状態の一次チェックを目的としています。プラグイン脆弱性は、指定したローカル DB に含まれる情報だけを検出します。
網羅的な脆弱性診断には、最新の脆弱性フィードや商用/公開 API と組み合わせてください。

NVD API を利用する場合、このツールは NVD API のデータを利用しますが、NVD により承認または認証されたものではありません。CVE の keyword 検索は補助情報であり、最終判断には CVE の references、CPE、影響バージョン、修正版を確認してください。

## License

MIT

## Authors

- Info Circus,Inc (https://www.infocircus.jp/)
- incmplt (https://www.incmplt.net/)
