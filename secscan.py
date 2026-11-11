#!/usr/bin/env python3
"""
secscan - one command for your whole security toolkit
-----------------------------------------------------
Combines header_checker.py, tls_checker.py and ghterm.py's repo scanner, and
adds three new modules:

    web      HTTP security headers + TLS + DNS/email audit of a site you own
    dns      DNS audit only (SPF, DMARC, DKIM, CAA, DNSSEC, dangling CNAMEs)
    repo     scan a local repo for red flags AND secrets hidden in git history
    history  git-history secret scanner only
    logs     analyze a web server access log for attacks

Keep header_checker.py, tls_checker.py, ghterm.py and secscan.py in ONE folder.
    pip install requests            (cryptography is optional, see tls_checker)

Examples:
    python secscan.py web example.com --html report.html
    python secscan.py dns example.com
    python secscan.py repo ./my-project
    python secscan.py history ./my-project --max-commits 500
    python secscan.py logs /var/log/nginx/access.log --html logs.html

ONLY scan sites and servers you own or have written permission to test.
Exit code is 1 if anything FAILs, so it works in CI pipelines too.
"""

import argparse
import collections
import gzip
import html
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from urllib.parse import unquote_plus, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import requests
    import header_checker as hc
    import tls_checker as tc
    import ghterm as gt
except ImportError as e:  # pragma: no cover
    sys.exit(f"Missing module: {e}\nKeep header_checker.py, tls_checker.py, ghterm.py and "
             "secscan.py in the same folder, and run: pip install requests")


# ---------- Shared finding model ----------
def F(area, title, status, detail="", fix=""):
    return {"area": area, "title": title, "status": status, "detail": detail, "fix": fix}


def norm(f):
    """Convert a header_checker / tls_checker Finding into the shared shape."""
    return F(f.category, f.name, f.status, f.detail, f.fix)


def section(name, findings, score=None):
    return {"name": name, "findings": findings, "score": score}


def short(text, n=90):
    text = (text or "").replace("\n", " ")
    return text if len(text) <= n else text[: n - 1] + "…"


# =====================================================================
# MODULE 1: DNS and email-security audit (uses DNS-over-HTTPS)
# =====================================================================
DOH = "https://cloudflare-dns.com/dns-query"
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim"]
COMMON_SUBS = ["www", "mail", "blog", "dev", "test", "staging", "api", "shop", "app", "docs",
               "status", "cdn", "git", "vpn", "portal", "support", "help", "beta"]
TAKEOVER_HINTS = ("github.io", "herokuapp.com", "s3.amazonaws.com", "amazonaws.com", "azurewebsites.net",
                  "cloudapp.net", "cloudfront.net", "netlify.app", "vercel.app", "pages.dev",
                  "surge.sh", "readthedocs.io", "ghost.io", "zendesk.com", "myshopify.com")


def doh(name, rtype, timeout=8, dnssec=False):
    params = {"name": name, "type": rtype}
    if dnssec:
        params["do"] = "1"
    r = requests.get(DOH, params=params, headers={"accept": "application/dns-json"}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _answers(resp, rtype_num):
    return [a for a in resp.get("Answer", []) if a.get("type") == rtype_num]


def _txt(resp):
    return [re.sub(r'"\s+"', "", a["data"]).strip('"') for a in _answers(resp, 16)]


def audit_dns(domain, lookup=doh):
    out = []
    A = "DNS"
    try:
        ns = lookup(domain, "NS")
    except requests.RequestException as e:
        return [F(A, "DNS lookup", "INFO", f"Could not reach the DNS-over-HTTPS resolver: {short(str(e))}")]
    if not _answers(ns, 2):
        return [F(A, "Name servers", "FAIL", f"No NS records found for {domain}.",
                  "Check the domain name and that it is delegated.")]
    out.append(F(A, "Name servers", "PASS", ", ".join(a["data"] for a in _answers(ns, 2))[:90]))

    def safe(name, rtype, **kw):
        try:
            return lookup(name, rtype, **kw)
        except requests.RequestException:
            return {}

    # SPF
    spf = [t for t in _txt(safe(domain, "TXT")) if t.lower().startswith("v=spf1")]
    if not spf:
        out.append(F("Email", "SPF", "WARN", "No SPF record: anyone can forge mail from this domain.",
                     "Add a TXT record like: v=spf1 include:<your-mail-provider> -all"))
    elif len(spf) > 1:
        out.append(F("Email", "SPF", "FAIL", "Multiple SPF records (invalid, receivers may ignore all).",
                     "Merge them into a single v=spf1 record."))
    elif re.search(r"\s\+all\b", spf[0]):
        out.append(F("Email", "SPF", "FAIL", "Policy ends in +all: ANY server may send as you.",
                     "Change +all to -all."))
    elif spf[0].rstrip().endswith("-all"):
        out.append(F("Email", "SPF", "PASS", short(spf[0])))
    else:
        out.append(F("Email", "SPF", "WARN", f"Weak ending (softfail or neutral): {short(spf[0])}",
                     "Use -all once you have confirmed every legitimate sender is listed."))

    # DMARC
    dm = [t for t in _txt(safe("_dmarc." + domain, "TXT")) if t.upper().startswith("V=DMARC1")]
    if not dm:
        out.append(F("Email", "DMARC", "FAIL", "No DMARC record: spoofed mail is not blocked or reported.",
                     "Add TXT _dmarc: v=DMARC1; p=quarantine; rua=mailto:you@" + domain))
    else:
        m = re.search(r"\bp=(\w+)", dm[0], re.I)
        pol = m.group(1).lower() if m else "none"
        if pol in ("reject", "quarantine"):
            out.append(F("Email", "DMARC", "PASS", f"Policy p={pol}."))
        else:
            out.append(F("Email", "DMARC", "WARN", "Policy is p=none (monitor only, spoofing still delivered).",
                         "Move to p=quarantine, then p=reject."))

    # DKIM (cannot enumerate selectors, so this is a best-effort probe)
    found = []
    for sel in DKIM_SELECTORS:
        for t in _txt(safe(f"{sel}._domainkey.{domain}", "TXT")):
            if "p=" in t or t.upper().startswith("V=DKIM1"):
                found.append(sel)
                break
    if found:
        out.append(F("Email", "DKIM", "PASS", "Selector(s) found: " + ", ".join(found)))
    else:
        out.append(F("Email", "DKIM", "INFO", "No key found under common selectors (inconclusive; "
                     "yours may use a custom selector)."))

    # CAA
    if _answers(safe(domain, "CAA"), 257):
        out.append(F(A, "CAA", "PASS", "Certificate issuance is restricted by CAA records."))
    else:
        out.append(F(A, "CAA", "WARN", "No CAA record: any certificate authority may issue certs for you.",
                     'Add a CAA record, e.g. 0 issue "letsencrypt.org"'))

    # DNSSEC (resolver-validated flag)
    if safe(domain, "A", dnssec=True).get("AD"):
        out.append(F(A, "DNSSEC", "PASS", "Responses validate with DNSSEC."))
    else:
        out.append(F(A, "DNSSEC", "INFO", "DNSSEC not validated for this domain."))

    # Dangling CNAMEs on common subdomains
    for sub in COMMON_SUBS:
        fqdn = f"{sub}.{domain}"
        cn = _answers(safe(fqdn, "CNAME"), 5)
        if not cn:
            continue
        target = cn[-1]["data"].rstrip(".")
        if safe(target, "A").get("Status") == 3:  # NXDOMAIN
            out.append(F("Takeover", f"Dangling CNAME: {fqdn}", "FAIL",
                         f"Points to {target}, which does not exist (subdomain takeover risk).",
                         "Delete the record or re-claim the target resource."))
        elif target.endswith(TAKEOVER_HINTS):
            out.append(F("Takeover", f"Third-party CNAME: {fqdn}", "INFO",
                         f"Points to {target}. Make sure that resource is still claimed by you."))
    if not any(f["area"] == "Takeover" for f in out):
        out.append(F("Takeover", "Dangling CNAMEs", "PASS",
                     f"None found among {len(COMMON_SUBS)} common subdomains (not exhaustive)."))
    return out


# =====================================================================
# MODULE 2: git-history secret scanner
# =====================================================================
CRED_RX = re.compile(r"""(?i)(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]""")
PLACEHOLDER_RX = re.compile(r"(?i)example|changeme|your[_-]|xxx|<|\$\{|placeholder|dummy|sample|\*\*\*|1234")
ENV_TEMPLATES = {".example", ".sample", ".template", ".dist", ".defaults"}


def _git(path, *args):
    return subprocess.run(["git", "-C", path, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def scan_history(path, max_commits=None):
    A = "Git history"
    if not shutil.which("git"):
        return [F(A, "git", "FAIL", "git is not installed or not on PATH.")]
    if _git(path, "rev-parse", "--git-dir").returncode != 0:
        return [F(A, "Repository", "FAIL", f"'{path}' is not a git repository.")]

    cmd = ["git", "-C", path, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff",
           "--date=short", "--pretty=format:@@C %h %ad"]
    if max_commits:
        cmd += ["-n", str(max_commits)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, encoding="utf-8", errors="replace")
    commit, fname, hits = "?", "?", {}
    for line in proc.stdout:
        if line.startswith("@@C "):
            commit = line[4:].strip()
        elif line.startswith("+++ "):
            fname = line[4:].strip()
            fname = fname[2:] if fname.startswith("b/") else fname
        elif line.startswith("+") and len(hits) < 200:
            chunk = line[1:2001]
            for label, rx in gt.SECRET_PATTERNS:
                m = rx.search(chunk)
                if m:
                    hits.setdefault((label, m.group(0)), (commit, fname))
            m = CRED_RX.search(chunk)
            if m and not PLACEHOLDER_RX.search(m.group(1)):
                hits.setdefault(("Hard-coded credential", m.group(1)), (commit, fname))
    proc.wait()

    findings = []
    for (label, value), (cm, fl) in hits.items():
        present = _git(path, "grep", "-qF", "--", value, "HEAD").returncode == 0
        where = f"{fl} (commit {cm})"
        if present:
            findings.append(F(A, f"{label} in current code", "WARN",
                              f"{where}: {gt.mask(value)}", "Move it to an env var / secret manager and rotate it."))
        else:
            findings.append(F(A, f"{label} deleted but STILL IN HISTORY", "FAIL",
                              f"{where}: {gt.mask(value)}",
                              "Deleting the file is not enough. Revoke/rotate the key, then purge "
                              "history (git filter-repo) if needed."))

    # sensitive files that were committed at any point
    names = _git(path, "log", "--all", "--name-only", "--pretty=format:").stdout.splitlines()
    for fn in sorted({n for n in names if n.strip()}):
        base = os.path.basename(fn).lower()
        ext = os.path.splitext(base)[1]
        template = base.startswith(".env.") and ext in ENV_TEMPLATES
        if (base in gt.SENSITIVE_NAMES or base.startswith(".env.") or ext in gt.SENSITIVE_EXTS) and not template:
            gone = _git(path, "cat-file", "-e", f"HEAD:{fn}").returncode != 0
            findings.append(F(A, "Sensitive file committed", "FAIL" if gone else "WARN",
                              f"{fn}" + (" (deleted, but recoverable from history)" if gone else ""),
                              "Rotate any credentials inside and add the file to .gitignore."))

    count = _git(path, "rev-list", "--all", "--count").stdout.strip() or "?"
    if not findings:
        findings.append(F(A, "Secrets in history", "PASS", f"No known secret patterns in {count} commits."))
    else:
        findings.append(F(A, "Coverage", "INFO", f"Scanned {count} commit(s)"
                          + (f" (limited to the newest {max_commits})" if max_commits else "") + "."))
    return findings


# =====================================================================
# MODULE 3: web access-log attack analyzer
# =====================================================================
LOG_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" '
                    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
ATTACKS = [
    ("SQL injection", re.compile(
        r"union(?:\s|/\*.*?\*/)+(?:all\s+)?select|information_schema|sleep\(\s*\d|benchmark\(|"
        r"\b(?:or|and)\b\s+\d+\s*=\s*\d+|'\s*(?:or|and)\s+'|;\s*drop\s+table|xp_cmdshell", re.I),
     "Use parameterized queries everywhere; put a WAF (ModSecurity + OWASP CRS) in front."),
    ("Cross-site scripting (XSS)", re.compile(
        r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img[^>]+src\s*=|alert\s*\(", re.I),
     "Encode output by context and set a strict Content-Security-Policy."),
    ("Path traversal", re.compile(
        r"\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini|win\.ini", re.I),
     "Normalize and validate file paths; never build paths from raw user input."),
    ("Command injection", re.compile(
        r"(?:;|\||`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b", re.I),
     "Never pass user input to a shell; use safe APIs with argument lists."),
    ("Log4Shell (JNDI) probe", re.compile(r"\$\{jndi:", re.I),
     "Patch Log4j to a fixed version and block ${jndi: at the edge."),
    ("Sensitive file probe", re.compile(
        r"/\.env\b|/\.git/|/\.svn/|/wp-config|/phpmyadmin|/\.aws/|/server-status|/\.DS_Store|"
        r"/backup\.(?:zip|sql|tar)|/cgi-bin/", re.I),
     "Make sure none of those paths are web-accessible; deny dotfiles and backups in the server config."),
]
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|zgrab|nuclei|acunetix|"
                        r"nessus|openvas|havij|w3af|feroxbuster|ffuf", re.I)
LOGIN_PATH = re.compile(r"/(?:wp-login\.php|xmlrpc\.php|login|signin|admin|user/login)\b", re.I)


def analyze_logs(path, login_threshold=10, scan_threshold=30):
    A = "Access log"
    opener = gzip.open if path.endswith(".gz") else open
    ips = collections.defaultdict(lambda: {"req": 0, "attacks": collections.Counter(), "login_fail": 0,
                                           "n404": 0})
    cats = collections.defaultdict(lambda: {"count": 0, "ips": set(), "ok": 0, "examples": []})
    total = unparsed = 0
    first = last = None
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            m = LOG_RE.match(line)
            if not m:
                unparsed += 1
                continue
            total += 1
            ip, status = m["ip"], int(m["status"])
            first = first or m["time"]
            last = m["time"]
            decoded = unquote_plus(unquote_plus(m["path"]))
            ua, ref = m["ua"] or "", m["ref"] or ""
            ips[ip]["req"] += 1

            hit_names = []
            for name, rx, _ in ATTACKS:
                target = f"{decoded} {ua} {ref}" if name.startswith("Log4Shell") else decoded
                if rx.search(target):
                    hit_names.append(name)
            if SCANNER_UA.search(ua):
                hit_names.append("Scanner tool user-agent")
            for name in hit_names:
                c = cats[name]
                c["count"] += 1
                c["ips"].add(ip)
                c["ok"] += 200 <= status < 300
                ips[ip]["attacks"][name] += 1
                if len(c["examples"]) < 3:
                    c["examples"].append(f"{ip} {status} {short(decoded, 70)}")

            if status in (401, 403) and LOGIN_PATH.search(decoded.split("?")[0]):
                ips[ip]["login_fail"] += 1
            if status == 404:
                ips[ip]["n404"] += 1

    out = []
    fixes = {n: fx for n, _, fx in ATTACKS}
    fixes["Scanner tool user-agent"] = "Block known scanner user-agents and rate-limit by IP."
    for name, c in sorted(cats.items(), key=lambda kv: -kv[1]["count"]):
        ok = f" {c['ok']} returned 2xx, check whether they worked." if c["ok"] else ""
        out.append(F(A, name, "FAIL",
                     f"{c['count']} request(s) from {len(c['ips'])} IP(s).{ok} e.g. " + " | ".join(c["examples"]),
                     fixes.get(name, "")))
    brute = sorted(((ip, d["login_fail"]) for ip, d in ips.items() if d["login_fail"] >= login_threshold),
                   key=lambda x: -x[1])
    if brute:
        out.append(F(A, "Brute-force login attempts", "FAIL",
                     ", ".join(f"{ip} ({n} failed)" for ip, n in brute[:5]),
                     "Rate-limit logins, add lockout/MFA, and block repeat offenders (fail2ban)."))
    noisy = sorted(((ip, d["n404"]) for ip, d in ips.items() if d["n404"] >= scan_threshold),
                   key=lambda x: -x[1])
    if noisy:
        out.append(F(A, "Aggressive path scanning (many 404s)", "WARN",
                     ", ".join(f"{ip} ({n} x 404)" for ip, n in noisy[:5]),
                     "Rate-limit or block these IPs; this is typical of automated discovery tools."))
    if not cats and not brute:
        out.append(F(A, "Attack patterns", "PASS", "No known attack signatures found in this log."))
    top = sorted(ips.items(), key=lambda kv: -kv[1]["req"])[:5]
    out.append(F(A, "Top talkers", "INFO", " | ".join(
        f"{ip}: {d['req']} req" + (f" [{', '.join(d['attacks'])}]" if d["attacks"] else "") for ip, d in top)))
    out.append(F(A, "Log summary", "INFO",
                 f"{total} requests parsed from {len(ips)} IP(s); {unparsed} unparsed line(s)."
                 + (f" Range: {first} to {last}." if first else "")))
    return out


# =====================================================================
# Orchestration, reporting
# =====================================================================
def web_sections(target, timeout, skip):
    url = target if target.startswith("http") else "https://" + target
    parsed = urlparse(url)
    host, port = parsed.hostname, parsed.port or 443
    sections = []

    if "headers" not in skip:
        try:
            session = requests.Session()
            session.headers["User-Agent"] = "secscan/1.0 (authorized security check)"
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            fs = (hc.check_transport(url, session, timeout) + hc.check_headers(resp.headers)
                  + hc.check_cookies(resp) + hc.check_cors(url, session, timeout)
                  + hc.check_info_leak(resp.headers))
            score, mx = sum(f.points for f in fs), sum(f.max_points for f in fs)
            sections.append(section("HTTP security headers", [norm(f) for f in fs],
                                    (score, mx, hc.grade(score / mx * 100))))
        except requests.RequestException as e:
            sections.append(section("HTTP security headers", [F("Connection", "Request", "FAIL",
                                    f"Could not reach {url}: {short(str(e))}")]))

    if "tls" not in skip:
        if parsed.scheme == "http":
            sections.append(section("TLS / certificate", [F("TLS", "TLS", "FAIL",
                                    "Site is served over plain HTTP, so there is no TLS to audit.",
                                    "Enable HTTPS.")]))
        else:
            fs, score, mx, letter, _ = tc.scan(host, port, timeout)
            sections.append(section("TLS / certificate", [norm(f) for f in fs], (score, mx, letter)))

    if "dns" not in skip and host and not re.fullmatch(r"[\d.]+|[\da-f:]+", host):
        parts = host.split(".")
        domain = ".".join(parts[-2:]) if len(parts) > 2 and len(parts[-1]) > 2 else host
        sections.append(section(f"DNS and email ({domain})", audit_dns(domain)))
    return sections


COLORS = {"FAIL": "91", "WARN": "93", "PASS": "92", "INFO": "2"}


def paint(status, text):
    return f"\033[{COLORS[status]}m{text}\033[0m" if sys.stdout.isatty() else text


def print_report(title, sections, quiet=False):
    print(f"\n{title}\nGenerated: {datetime.now():%Y-%m-%d %H:%M:%S}\n" + "=" * 72)
    counts = collections.Counter()
    for sec in sections:
        head = sec["name"]
        if sec["score"]:
            s, mx, g = sec["score"]
            head += f"   score {s}/{mx} ({round(s / mx * 100)}%)  grade {g}"
        print(f"\n[{head}]")
        for f in sec["findings"]:
            counts[f["status"]] += 1
            if quiet and f["status"] == "PASS":
                continue
            print(f"  {paint(f['status'], f['status']):<{4 + (9 if sys.stdout.isatty() else 0)}} "
                  f"{f['title']}")
            if f["detail"]:
                print(f"       {f['detail']}")
            if f["fix"] and f["status"] in ("FAIL", "WARN"):
                print(f"       Fix: {f['fix']}")
    print("\n" + "=" * 72)
    print(f"{counts['FAIL']} failing, {counts['WARN']} warnings, {counts['PASS']} passing\n")
    return counts


def write_html(path, title, sections):
    colors = {"FAIL": "#c62828", "WARN": "#b26a00", "PASS": "#2e7d32", "INFO": "#555"}
    e = html.escape
    body = []
    for sec in sections:
        head = e(sec["name"])
        if sec["score"]:
            s, mx, g = sec["score"]
            head += f" <span class='g'>grade {e(str(g))} &middot; {s}/{mx}</span>"
        rows = "".join(
            f"<tr><td style='color:{colors[f['status']]};font-weight:700'>{f['status']}</td>"
            f"<td>{e(f['title'])}</td><td>{e(f['detail'])}</td><td>{e(f['fix'])}</td></tr>"
            for f in sec["findings"])
        body.append(f"<h2>{head}</h2><table><tr><th>Status</th><th>Check</th><th>Detail</th>"
                    f"<th>Fix</th></tr>{rows}</table>")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>
<style>:root{{color-scheme:light dark}}body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1000px;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin-bottom:1.5rem}}td,th{{border:1px solid #8885;padding:6px 8px;
text-align:left;vertical-align:top;font-size:.9rem}}th{{background:#8883}}.g{{font-size:.9rem;font-weight:400;opacity:.8}}</style>
</head><body><h1>{e(title)}</h1><p>{datetime.now():%Y-%m-%d %H:%M}</p>{''.join(body)}</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def confirm_authorized(what, yes):
    if yes:
        return
    ans = input(f"Do you own or have written permission to test {what}? [y/N] ")
    if ans.strip().lower() != "y":
        sys.exit("Aborted. Only scan targets you are authorized to test.")


def finish(args, title, sections):
    counts = print_report(title, sections, args.quiet)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"title": title, "sections": sections}, fh, indent=2)
        print(f"JSON saved to {args.json}")
    if args.html:
        write_html(args.html, title, sections)
        print(f"HTML saved to {args.html}")
    sys.exit(1 if counts["FAIL"] else 0)


def cmd_web(a):
    confirm_authorized(a.target, a.yes)
    skip = {s.strip() for s in (a.skip or "").split(",") if s.strip()}
    finish(a, f"secscan web report: {a.target}", web_sections(a.target, a.timeout, skip))


def cmd_dns(a):
    confirm_authorized(a.domain, a.yes)
    finish(a, f"secscan DNS report: {a.domain}", [section("DNS and email", audit_dns(a.domain))])


def _need_dir(path):
    if not os.path.isdir(path):
        sys.exit(f"'{path}' is not a folder.")


def cmd_repo(a):
    _need_dir(a.path)
    items, scanned, skipped = gt.scan_repo(a.path)
    mapped = [F("Files", f"{cat}: {path}", "FAIL" if sev == "high" else "WARN", detail)
              for sev, cat, path, detail in items]
    if not mapped:
        mapped = [F("Files", "Red-flag scan", "PASS", f"No known red flags in {scanned} text files.")]
    secs = [section(f"Repo files ({scanned} scanned, {skipped} skipped)", mapped)]
    if not a.no_history:
        secs.append(section("Git history", scan_history(a.path, a.max_commits)))
    finish(a, f"secscan repo report: {a.path}", secs)


def cmd_history(a):
    _need_dir(a.path)
    finish(a, f"secscan history report: {a.path}", [section("Git history", scan_history(a.path, a.max_commits))])


def cmd_logs(a):
    if not os.path.isfile(a.logfile):
        sys.exit(f"'{a.logfile}' is not a file.")
    finish(a, f"secscan log report: {a.logfile}",
           [section("Access log analysis", analyze_logs(a.logfile, a.login_threshold, a.scan_threshold))])


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--html", help="write an HTML report")
    common.add_argument("--json", help="write a JSON report")
    common.add_argument("--quiet", action="store_true", help="hide PASS lines")

    p = argparse.ArgumentParser(prog="secscan", description="All-in-one security toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("web", parents=[common], help="headers + TLS + DNS for a site you own")
    s.add_argument("target", help="domain or URL")
    s.add_argument("--skip", help="comma list to skip: headers,tls,dns")
    s.add_argument("--timeout", type=int, default=10)
    s.add_argument("--yes", action="store_true", help="confirm you are authorized")
    s.set_defaults(fn=cmd_web)

    s = sub.add_parser("dns", parents=[common], help="DNS and email-security audit")
    s.add_argument("domain")
    s.add_argument("--yes", action="store_true", help="confirm you are authorized")
    s.set_defaults(fn=cmd_dns)

    s = sub.add_parser("repo", parents=[common], help="scan a local repo (files + git history)")
    s.add_argument("path")
    s.add_argument("--no-history", action="store_true", help="skip the git-history scan")
    s.add_argument("--max-commits", type=int, help="only scan the newest N commits")
    s.set_defaults(fn=cmd_repo)

    s = sub.add_parser("history", parents=[common], help="scan git history for secrets")
    s.add_argument("path")
    s.add_argument("--max-commits", type=int)
    s.set_defaults(fn=cmd_history)

    s = sub.add_parser("logs", parents=[common], help="analyze a web access log (nginx/apache, .gz ok)")
    s.add_argument("logfile")
    s.add_argument("--login-threshold", type=int, default=10, help="failed logins per IP to flag")
    s.add_argument("--scan-threshold", type=int, default=30, help="404s per IP to flag")
    s.set_defaults(fn=cmd_logs)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
