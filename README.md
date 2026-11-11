# secscan

`secscan.py` combines site, DNS, local repository, Git-history, and web access
log checks into one CLI. It can print findings and optionally write JSON or
HTML reports. Site and DNS checks require explicit authorization; only use
them on systems you own or have permission to assess.

## Requirements

- Python 3.8 or newer
- `requests`
- Git for repository history checks
- `cryptography` is optional and can provide additional TLS certificate checks

Install dependencies:

```bash
python -m pip install requests
# Optional:
python -m pip install cryptography
```

## Important: companion module names

`secscan.py` imports `header_checker.py`, `ghterm.py`, and `tls_checker.py` from
the same directory. This folder contains `tls.py`, not `tls_checker.py`, so
the current set of filenames does not satisfy that import. Before running
`secscan.py`, make the TLS module available under the expected
`tls_checker.py` name or update the import in `secscan.py` to match the
filename. Keep the companion modules alongside `secscan.py`.

## Usage

```bash
python secscan.py web example.com --html web-report.html
python secscan.py web https://example.com --json web-report.json
python secscan.py dns example.com
python secscan.py repo ./my-project
python secscan.py repo ./my-project --no-history
python secscan.py history ./my-project --max-commits 500
python secscan.py logs /var/log/nginx/access.log --html access-report.html
```

`web` checks HTTP headers, TLS, and DNS/email configuration; `--skip` accepts a
comma-separated list of checks to skip (`headers,tls,dns`). `dns` checks DNS
and email security records. `repo` scans files and Git history, while
`history` scans only Git history. `logs` analyzes an nginx/Apache-style access
log, including gzip-compressed logs. The report flags `--json`, `--html`, and
`--quiet` are available on each subcommand.

`web` and `dns` prompt for authorization unless `--yes` is supplied. The
program exits with status 1 when a report contains a `FAIL`, which is useful
for CI pipelines.

## Limitations

These are heuristic checks, not a guarantee of security. Review findings
before taking action, and do not run scans against systems without permission.
