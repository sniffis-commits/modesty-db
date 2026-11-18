<!-- logo -->
<p align="center">
  <img src="https://modesty.eu.org/images/logos/modesty-db.svg" alt="Modesty" width="96" height="96">
</p>

# modesty-db

> Free domain database + weekly releases

Blocklist importer and tooling for `nsfw.sqlite`, the free 4.7M-domain database. Also hosts the weekly `nsfw.sqlite-vYYYY.MM.DD` release asset that the website downloads.

## Details

| | |
|---|---|
| Language | Python |
| License | MIT (code) · data sources have per-source licenses (see LICENSES) |
| Website | [https://modesty.eu.org](https://modesty.eu.org) |
| Full repository map | [REPO_MAP.md](https://github.com/sniffis-commits/nfsw_scanner/blob/main/docs/REPO_MAP.md) |
| Status | Scaffold — code is being split from the private monorepo |

## Quick start

```sh
python packages/nsfw-db/src/import_blocklists.py
```

## About Modesty

Modesty is a privacy-first NSFW content scanner. Scanning runs locally by
default; uploads are always opt-in. The public packages are split out of the
private monorepo into standalone repositories — see the
[repository map](https://github.com/sniffis-commits/nfsw_scanner/blob/main/docs/REPO_MAP.md) for the full local-to-GitHub naming.

Licensed under MIT (code) · data sources have per-source licenses (see LICENSES). See the website's
[license review](https://modesty.eu.org/?p=licenses) for third-party data and model terms.
