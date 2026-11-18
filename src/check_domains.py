"""Domain liveness evaluator for the NSFW `known_domains` database.

The blocklist DBs contain millions of historical domains; entries whose
domains have been deleted or whose sites were dropped long ago still answer
"rating 10" forever. This tool measures *whether a domain still exists*:

1. DNS check — raw UDP queries sent **directly to specific resolvers**
   (default: 8.8.8.8 and 1.1.1.1, both required). When the two resolvers
   disagree, or one answers NXDOMAIN, the split is recorded. Because we
   build the DNS packet ourselves, the system resolver cannot interfere.
2. Whois check — raw TCP/43 request, IANA-first, following the
   "ReferralServer: whois://..." pointer to the registry/registrar
   server (custom clients otherwise). Extracts creation/expiry dates and
   registrar when present — a registered-but-expired domain is clearly
   flagged: expiry in the past + status renewal/pending → dead-parked.

Statuses written back into the `domain_health` table (created on first run):
  alive   — at least one resolver returns an A record (DNS decides; whois
            parse quirks on subdomains never downgrade a resolving host)
  parked  — NXDOMAIN on every resolver but whois still shows a registration
            (dropped/expired zone still owned by someone)
  dead    — NXDOMAIN everywhere and whois shows no registration
  error   — network-level failure (resolvers unreachable, no reply)

The column is called `status` (the liveness state of the domain). The
*verdict* is the unsafe-content rating 1-10 and lives in `known_domains`.

Run:
  python packages/nsfw-db/src/check_domains.py              # 250 random domains
  python packages/nsfw-db/src/check_domains.py --limit 50 --age-days 90
  python packages/nsfw-db/src/check_domains.py --dry-run     # don't write back
  python packages/nsfw-db/src/check_domains.py --db PATH --concurrency 16
"""

import os
import re
import socket
import sqlite3
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "nsfw-webservice", "src")))

DEFAULT_RESOLVERS = ("8.8.8.8", "1.1.1.1")
DNS_PORT = 53
WHOIS_TLD_SERVER = "whois.iana.org"
WHOIS_PORT = 43
WHOIS_TIMEOUT = 8
DNS_TIMEOUT = 4

HEALTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_health (
  domain TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  nxdomain_resolvers TEXT,
  alive_resolvers TEXT,
  whois_server TEXT,
  whois_registered TEXT,
  whois_expiry_date TEXT,
  whois_registrar TEXT,
  checked_utc REAL NOT NULL,
  error TEXT
);
"""

HEALTH_COLUMNS = ("domain", "status", "nxdomain_resolvers", "alive_resolvers",
                  "whois_server", "whois_registered", "whois_expiry_date",
                  "whois_registrar", "checked_utc", "error")


def ensure_health_schema(conn):
    """Creates `domain_health` and migrates the old `verdict` column.

    The column was renamed to `status` (liveness is a *status*, the safety
    rating is the *verdict*).  The old table is rebuilt: the legacy
    `verdict` column was NOT NULL, so it would reject every insert that
    only writes `status`.
    """
    conn.executescript(HEALTH_SCHEMA)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(domain_health)")}
    if "verdict" in cols:
        def pick(name):
            return name if name in cols else "NULL"

        # Rebuild without the legacy column; `status` wins when it is
        # already there, `verdict` fills the gap otherwise.
        status_expr = ("COALESCE(status, verdict)" if "status" in cols
                       else "verdict")
        select = ", ".join([
            pick("domain"), status_expr, pick("nxdomain_resolvers"),
            pick("alive_resolvers"), pick("whois_server"),
            pick("whois_registered"), pick("whois_expiry_date"),
            pick("whois_registrar"), pick("checked_utc"), pick("error")])
        conn.execute("DROP TABLE IF EXISTS domain_health_migrate")
        conn.execute(
            "CREATE TABLE domain_health_migrate (\n%s)" % ",\n".join(
                "  %s %s" % (name, "TEXT PRIMARY KEY" if name == "domain"
                             else "TEXT NOT NULL" if name == "status"
                             else "REAL NOT NULL" if name == "checked_utc"
                             else "TEXT")
                for name in HEALTH_COLUMNS))
        conn.execute(
            "INSERT INTO domain_health_migrate (%s) SELECT %s FROM domain_health"
            % (", ".join(HEALTH_COLUMNS), select))
        conn.execute("DROP TABLE domain_health")
        conn.execute("ALTER TABLE domain_health_migrate RENAME TO domain_health")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_health_status "
                 "ON domain_health (status)")
    conn.commit()


# ---------------------------------------------------------------- DNS ----

def _dns_encode_name(name):
    out = bytearray()
    for part in name.rstrip(".").split("."):
        out.append(len(part))
        out.extend(part.encode("idna") if not part.isascii() else part.encode())
    out.append(0)
    return bytes(out)


def _dns_query(resolver_ip, domain, timeout=DNS_TIMEOUT):
    """One A-record query against one resolver. Returns (rcode, [ips])."""
    tid = os.urandom(2)
    # QTYPE=A(1), QCLASS=IN(1), RD flag set
    header = struct.pack("!HHHHHH", int.from_bytes(tid, "big"), 0x0100, 1, 0, 0, 0)
    tail = b"\x00\x01\x00\x01"
    packet = header + _dns_encode_name(domain) + tail
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (resolver_ip, DNS_PORT))
        data, _addr = sock.recvfrom(4096)
    finally:
        sock.close()
    if len(data) < 12 or data[:2] != tid:
        raise ValueError("bad DNS reply")
    ( _flags, qd, an, _ns, _ar ) = struct.unpack("!HHHHH", data[2:12])
    rcode = _flags & 0x0F
    ips = []
    if rcode == 0 and an:
        # skip the question
        idx = 12
        while data[idx] != 0:
            idx += data[idx] + 1
        idx += 5
        for _ in range(an):
            # name (possibly compressed)
            if data[idx] & 0xC0 == 0xC0:
                idx += 2
            else:
                while data[idx] != 0:
                    idx += data[idx] + 1
                idx += 1
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[idx:idx + 10])
            idx += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(data[idx:idx + rdlen]))
            idx += rdlen
    return rcode, ips


def dns_check(domain, resolvers=DEFAULT_RESOLVERS):
    """Returns (alive_resolvers, nxdomain_resolvers)."""
    alive, nx = [], []
    for ip in resolvers:
        rcode, _ips = _dns_query(ip, domain)
        if rcode == 0:
            alive.append(ip)
        elif rcode == 3:  # NXDOMAIN
            nx.append(ip)
    return alive, nx


# -------------------------------------------------------------- whois ----

_WHOIS_REFERRAL = re.compile(r"ReferralServer:\s*whois://([^\s/]+)", re.IGNORECASE)
_WHOIS_SERVER = re.compile(r"whois:\s+([a-z0-9.\-]+\.[a-z]{2,})", re.IGNORECASE)
_WHOIS_EXPIRY = re.compile(
    r"(?:Expir(?:y|ation) Date|Registry Expiry Date|expires)[.:\s]*([0-9]{4}-[0-9]{2}-[0-9]{2})", re.IGNORECASE)
_WHOIS_CREATED = re.compile(
    r"(?:Creation Date|Created on|created)[.:\s]*([0-9]{4}-[0-9]{2}-[0-9]{2})", re.IGNORECASE)
_WHOIS_REGISTRAR = re.compile(r"Registrar:\s*(.+)", re.IGNORECASE)
_WHOIS_STATUS = re.compile(r"Domain Status:\s*(\S+)", re.IGNORECASE)
_NO_MATCH = re.compile(
    r"(no match|not found|no entries found|available|status:\s*free|status:\s*available)", re.IGNORECASE)


def _whois_query(server, query, timeout=WHOIS_TIMEOUT):
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((server, WHOIS_PORT))
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")
    finally:
        sock.close()


def _whois_lookup(domain):
    """One whois lookup (IANA -> referral chain) for exactly `domain`."""
    server = WHOIS_TLD_SERVER
    text = _whois_query(server, domain)
    got = None
    for _attempt in range(3):           # follow referral chains
        referral = None
        m = _WHOIS_REFERRAL.search(text)
        if m:
            referral = m.group(1).lower().rstrip(".")
        else:
            m2 = _WHOIS_SERVER.search(text)
            if m2:
                referral = m2.group(1).lower()
        if not referral or referral == got or referral in ("whois.iana.org",):
            break
        got = referral
        try:
            text = _whois_query(referral, domain)
        except OSError:
            break
    server = got or server
    expiry = _WHOIS_EXPIRY.search(text)
    created = _WHOIS_CREATED.search(text)
    registrar = _WHOIS_REGISTRAR.search(text)
    status = _WHOIS_STATUS.search(text)
    return {
        "server": server,
        "query_domain": domain,
        "registered": bool(created or expiry or registrar) and not _NO_MATCH.search(text),
        "no_match": bool(_NO_MATCH.search(text)),
        "expiry_date": expiry.group(1) if expiry else None,
        "creation_date": created.group(1) if created else None,
        "registrar": (registrar.group(1).strip()[:120] if registrar else None),
        "status": status.group(1) if status else None,
        "raw_len": len(text),
    }


def whois_check(domain):
    """Returns dict: server / registered / expiry / registrar / status / no_match.

    Registries expect the *registrable* domain, so a host like
    ``foo.blogspot.com`` is walked up to ``blogspot.com`` when the full
    host answers nothing.  Without this, every subdomain of a shared host
    looks unregistered and the verdict used to collapse to "unknown".
    """
    labels = domain.split(".")
    last = None
    for i in range(max(0, len(labels) - 2) + 1):     # full host, then parents
        candidate = ".".join(labels[i:])
        if "." not in candidate:
            break
        info = _whois_lookup(candidate)
        last = info
        if info["registered"]:
            return info
        if info["no_match"] and i >= len(labels) - 2:
            # no match on the registrable domain itself -> truly available
            return info
    return last or _whois_lookup(domain)


# -------------------------------------------------------------- single ----

def evaluate_domain(domain, resolvers=DEFAULT_RESOLVERS, with_whois=True):
    """Returns a `domain_health` row (dict) for one domain."""
    row = {"domain": domain, "checked_utc": time.time(), "error": None,
           "nxdomain_resolvers": None, "alive_resolvers": None,
           "whois_server": None, "whois_registered": None,
           "whois_expiry_date": None, "whois_registrar": None}
    try:
        alive, nx = dns_check(domain, resolvers)
        row["alive_resolvers"] = ",".join(alive)
        row["nxdomain_resolvers"] = ",".join(nx)
    except (OSError, ValueError) as exc:
        row["status"] = "error"
        row["error"] = f"dns: {exc}"
        return row

    if with_whois:
        try:
            who = whois_check(domain)
            row["whois_server"] = who["server"]
            row["whois_registered"] = int(who["registered"])
            row["whois_expiry_date"] = who["expiry_date"]
            row["whois_registrar"] = who["registrar"]
        except (OSError, UnicodeError) as exc:
            row["error"] = f"whois: {exc}"

    registered = row.get("whois_registered") == 1
    all_resolvers = len(resolvers)

    # DNS is authoritative for *existence*: if any resolver resolves the
    # host it is alive, regardless of how whois parsed (sub-hosted domains,
    # registrar quirks, or a whois server that refuses the subdomain).
    if alive:
        row["status"] = "alive"
    elif not nx:
        row["status"] = "error"
    elif len(nx) >= all_resolvers:
        # NXDOMAIN everywhere. A registered-but-unresolvable domain is
        # parked/expired; an unregistered one is dead.
        row["status"] = "parked" if registered else "dead"
    else:
        row["status"] = "dead"
    return row


# ---------------------------------------------------------------- main ----

def default_db_path():
    return os.path.normpath(os.path.join(HERE, "..", "data", "nsfw.sqlite"))


def pick_domains(conn, limit, age_days=None, statuses=("alive", "parked")):
    """Random candidate domains: prefer ones never checked, else stale checks.

    Note: unchecked domains have d.status/d.domain = NULL (LEFT JOIN miss),
    so "NOT IN (...)" alone can never match them — the explicit IS NULL
    branches below are required.
    """
    params = []
    conds = []
    if age_days is not None:
        conds.append("(d.domain IS NULL OR d.checked_utc < ?)")
        params.append(time.time() - age_days * 86400)
    else:
        conds.append("d.domain IS NULL")
    if statuses:
        conds.append("(d.status IS NULL OR d.status NOT IN (%s))"
                     % ",".join("?" * len(statuses)))
        params.extend(statuses)
    sql = ("SELECT k.domain FROM known_domains k "
           "LEFT JOIN domain_health d ON d.domain = k.domain "
           "WHERE (%s) ORDER BY RANDOM() LIMIT ?" % "\n             OR ".join(conds))
    params.append(int(limit))
    return [r[0] for r in conn.execute(sql, params)]


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Dead-domain evaluator for nsfw.sqlite")
    ap.add_argument("--db", default=default_db_path())
    ap.add_argument("--limit", type=int, default=250, help="how many domains to check")
    ap.add_argument("--concurrency", type=int, default=12)
    ap.add_argument("--age-days", type=float, default=30,
                    help="recheck domains whose last health check is older than this")
    ap.add_argument("--resolvers", default="8.8.8.8,1.1.1.1")
    ap.add_argument("--no-whois", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    resolvers = tuple(r.strip() for r in args.resolvers.split(",") if r.strip())
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    ensure_health_schema(conn)

    domains = pick_domains(conn, args.limit, args.age_days)
    print(f"evaluating {len(domains)} domains "
          f"(resolvers {resolvers}, whois={'off' if args.no_whois else 'on'})")

    counts = {}
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        rows = list(ex.map(lambda d: evaluate_domain(d, resolvers, not args.no_whois),
                           domains))
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    if not args.dry_run:
        conn.executemany(
            "INSERT OR REPLACE INTO domain_health "
            "(domain, status, nxdomain_resolvers, alive_resolvers,"
            " whois_server, whois_registered, whois_expiry_date,"
            " whois_registrar, checked_utc, error) VALUES "
            "(:domain,:status,:nxdomain_resolvers,:alive_resolvers,"
            ":whois_server,:whois_registered,:whois_expiry_date,"
            ":whois_registrar,:checked_utc,:error)",
            rows)
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES "
                     "('domain_health_checked_utc', ?)", (time.time(),))
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES "
                     "('domain_health_total', ?)", (str(len(rows)),))
        conn.commit()
    conn.close()
    print(f"statuses: {counts}" + ("  (dry run, nothing written)" if args.dry_run else ""))
    if not counts:
        print("nothing checked — did the DB have any known_domains?")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
