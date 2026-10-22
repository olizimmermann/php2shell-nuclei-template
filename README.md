# php2shell-nuclei-template

Read-only [nuclei](https://github.com/projectdiscovery/nuclei) template that finds
exposed `phpinfo()` pages and reports which **php2shell** attack chains
(CVE-2026-109618 / CVE-2026-109619) the host is exposed to, based on PHP
version, Server API and session settings.

Research: <https://github.com/ikow/php2shell-poc> by Qi Deng (@ikow).

> **Authorized testing only.** The template sends plain GET requests to a few
> common phpinfo paths. It sends no multipart bodies, writes no session files
> and does not trigger the OOM path.

## Findings

One result per matching chain:

| Matcher | Fires when |
| --- | --- |
| `chain-d-mod-php` | Affected PHP on Apache mod_php (`Apache 2.0 Handler` / `Apache 2 Handler`) |
| `chain-e-fpm` | Affected PHP on PHP-FPM with `session.upload_progress.enabled` On |
| `chain-a-preconditions` | `upload_progress` On, `cleanup` Off, `use_strict_mode` Off — independent of version, Chain A still works on patched PHP if the app has an LFI |
| `affected-version` | Affected PHP on any other SAPI (CGI/FastCGI, built-in server, …) |

Affected: 5.4.0 – 8.2.34, 8.3.0 – 8.3.35, 8.4.0 – 8.4.26, 8.5.0 – 8.5.11.
Fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12.

Each result carries the extracted values, e.g.
`php=8.2.20 sapi=Apache 2.0 Handler upload_progress=On cleanup=Off strict_mode=Off`.

## Usage

```bash
nuclei -t php2shell-phpinfo-exposure.yaml -u https://target.example
nuclei -t php2shell-phpinfo-exposure.yaml -l targets.txt -jsonl -o results.jsonl
```

Probed paths: `/phpinfo.php`, `/info.php`, `/php_info.php`, `/php-info.php`,
`/test.php`, `/i.php`, `/pi.php`, `/php.php` (stops at the first hit).

## Verification

Validated with nuclei v3.11.1 against 19 lab containers built from official
`php:*` images:

| Lab | Result |
| --- | --- |
| 5.6 / 7.4 / 8.2.20 / 8.3.35 / 8.5.11 mod_php | `chain-d-mod-php` |
| 8.1 / 8.4.26 PHP-FPM + nginx | `chain-e-fpm` |
| 8.2.20 php-cgi + nginx, 8.2.20 built-in server | `affected-version` |
| 7.4 mod_php, 8.1 FPM, 8.5.12 with `cleanup=Off` | `chain-a-preconditions` (plus chain-d/e where affected) |
| 8.3.36, 8.4.27 (first fixed releases) | no finding |
| 8.4.26 FPM with `upload_progress=Off` | no finding |
| 8.5.12 with `use_strict_mode=On` | no finding |
| `phpinfo(INFO_GENERAL)` / `phpinfo(INFO_MODULES)` only | partial values reported, correct matcher |
| Prose page mentioning "phpinfo()" and "PHP Version", catch-all 200 server | no finding |

Handles PHP ≤ 8.1 printing booleans as `1`/`0` and PHP 8.5's renamed
`Apache 2 Handler` SAPI.

## Limitations

- Needs an exposed phpinfo page; hosts without one are not assessed. Pair with
  an `X-Powered-By` version check for wider coverage.
- Version-based: distribution packages with backported fixes report an older
  upstream version and will show as affected.
- Reports exposure conditions, not confirmed exploitability.
