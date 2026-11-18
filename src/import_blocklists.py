"""Import DNS-blocker lists into the SQLite known-domains table.

Known adult domains answer rating 10 without any scan. Every source is
optional -- failures are logged and skipped, and the run fails only if
nothing was imported at all.

Run:  python packages/nsfw-db/src/import_blocklists.py [--db PATH]
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..",
    "nsfw-webservice", "src")))
import cache_db  # noqa: E402

import requests  # noqa: E402

SOURCES = [
    # (name, url, format, rating)
    ("stevenblack-porn",
     "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
     "hosts", 10),
    ("firebog-prigent-adult",
     "https://v.firebog.net/hosts/Prigent-Adult.txt",
     "hosts", 10),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (NSFW research scanner; blocklist import)"}
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,}$")
SKIP = {"localhost", "localhost.localdomain", "local", "localhost6",
        "ip6-localhost", "ip6-loopback"}


def parse_hosts(text):
    """Yields bare domains from /etc/hosts-style content."""
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or "." not in parts[0] and parts[0] not in ("0.0.0.0", "127.0.0.1", "::1", "::"):
            # Not an IP-led hosts line; accept a bare-domain line instead.
            candidates = parts if len(parts) == 1 else []
        else:
            candidates = parts[1:]
        for raw in candidates:
            domain = raw.lower().rstrip(".")
            if domain in SKIP or not DOMAIN_RE.match(domain):
                continue
            yield domain


def fetch(url, retries=3):
    last = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=30, headers=HEADERS)
            resp.raise_for_status()
            return resp.text
        except Exception as exc:
            last = exc
            print(f"  attempt {attempt}/{retries} failed: {exc}")
            time.sleep(2 * attempt)
    raise last


def default_db_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "data", "nsfw.sqlite"))


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Import DNS-blocker lists")
    parser.add_argument("--db", default=default_db_path())
    parser.add_argument("--backfill-sources", action="store_true",
                        help="After import, map legacy known_domains.source "
                             "text to sources.id (one-time migration helper)")
    args = parser.parse_args(argv)

    db = cache_db.CacheDB(args.db)
    total = 0
    summary = {}
    for name, url, format_, rating in SOURCES:
        source = db.source_info(slug=name)
        license_note = source["license"] if source else "unknown"
        print(f"[{name}] {url}")
        print(f"  display: {source['display_name'] if source else name} | license: {license_note}")
        try:
            text = fetch(url)
        except Exception as exc:
            print(f"  SKIPPED ({exc})")
            continue
        domains = sorted(set(parse_hosts(text)))
        removed = db.removed_domains()
        if removed:
            skipped = len(removed)
            domains = [d for d in domains if d not in removed]
            print(f"  skipping {skipped} domain(s) removed by an admin")
        count = db.add_domains([(d, rating, name) for d in domains])
        summary[name] = count
        total += count
        print(f"  imported {count} domains (source_id={db.source_id(name)})")
    db.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    ("blocklist_updated_utc", str(time.time())))
    db.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    ("blocklist_sources", ",".join(sorted(summary))))
    db.conn.commit()
    if args.backfill_sources:
        moved = db.backfill_source_ids()
        print(f"backfilled source_id on {moved} legacy rows")
    print(f"total new/updated: {total} -> {args.db}")
    db.close()
    if total == 0:
        raise SystemExit("no domains imported from any source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
