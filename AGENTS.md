# AGENTS.md — Agent Developer Guide for Website Monitor

This document serves as the guide for AI coding agents and human contributors maintaining or extending the **Website Monitor** repository.

---

## 1. Project Overview & Architecture

`website-monitor` is an automated Python monitoring utility designed to run daily (via cron or Windows Task Scheduler). It audits a list of URLs and evaluates:
- **HTTP Availability, Response Time & Status**: HTTP status codes, response time (ms), redirects, and homepage HTML content validity.
- **Hosting Problem Signatures**: Underlying detection of hosting suspension notices, resource exhaustion (e.g. HTTP 508), or parked pages (reported under Issues & Potential Expiration).
- **DNS Resolution**: IPv4 (`A`) and IPv6 (`AAAA`) resolution.
- **SSL / TLS Certificate**: Expiration date, days remaining, certificate validation status.
- **Domain Expiration**: Public RDAP (Registration Data Access Protocol) and fallback port-43 WHOIS queries.
- **Network Metadata**: Public IP range / Autonomous System registration data via RDAP.

Outputs include dated CSV spreadsheets, HTML visual reports, and rotating execution logs.

### Directory Structure

```text
website-monitor/
├── data/
│   └── urls.txt                 # Input URLs (one per line, comments '#' supported)
├── reports/                     # Output directory for daily reports (CSV & HTML)
├── logs/                        # Rotating execution logs (website_monitor.log)
├── tests/                       # Unit and integration test suite
│   └── test_website_monitor.py  # Unittest test cases
├── website_monitor.py           # Main monolithic engine (CLI, checkers, reporter)
├── check_duplicates.py          # Utility script to check duplicate URLs in data/urls.txt
├── requirements.txt             # Production dependencies
├── README.md                    # User-facing documentation & scheduler setup
└── AGENTS.md                    # Agent architecture and development guide
```

---

## 2. Environment Setup & Tooling

### Python Environment
- Requires **Python 3.10+**.
- A virtual environment is located at `.venv/`.

### Installation Commands
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Windows PowerShell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

### Dependencies
- `requests`: Used for HTTP availability checks, RDAP domain queries, and RDAP IP network lookups.
- `cryptography`: Used to parse X.509 certificate timestamps when standard TLS certificate verification fails.
- Standard Library: `socket`, `ssl`, `ipaddress`, `csv`, `datetime`, `argparse`, `logging`, `urllib.parse`.

---

## 3. Common Development Commands

### Running the Monitor
```bash
# Default run (reads data/urls.txt, outputs to reports/ and logs/)
.venv/bin/python3 website_monitor.py

# Custom options
.venv/bin/python3 website_monitor.py \
    --urls-file data/urls.txt \
    --reports-dir reports \
    --logs-dir logs \
    --connect-timeout 5.0 \
    --read-timeout 15.0 \
    --warning-days 30
```

### Running Tests
Unit tests use Python's built-in `unittest` framework:
```bash
# Run all tests
.venv/bin/python3 -m unittest discover tests/

# Run a specific test class or method
.venv/bin/python3 -m unittest tests.test_website_monitor.URLTests
.venv/bin/python3 -m unittest tests.test_website_monitor.ReportTests.test_normal_run_creates_csv_and_html_reports
```

### Sandbox & Network Rules
- **Sandboxed Execution**: Unit tests (`tests/test_website_monitor.py`) must never make live network calls. All socket, HTTP, SSL, and RDAP calls are mocked or run against local in-process `http.server` instances.
- **Live Monitoring**: When running `website_monitor.py` against external targets, sandbox network permissions are required.

---

## 4. Core Check Pipeline & Status Classification

For each URL in `data/urls.txt`, `check_website` executes the following sequence:

```
Raw URL -> normalize_url() -> resolve_host() [DNS]
  │                                    │
  ├── lookup_ip_network_info() (RDAP)  ├── check_ssl_certificate() [TLS]
  │                                    │
  ├── lookup_domain_expiration() ◄─────┴── HTTP GET -> detect_hosting_indicators()
  │     ├── 1. RDAP (rdap.org)
  │     └── 2. WHOIS fallback (e.g. whois.get.bd)
  │
  └── classify_result() -> CSV & HTML Report
```

### Classification Statuses
1. **`WORKING`**:
   - HTTP status 200–399.
   - DNS resolved.
   - SSL valid (if HTTPS) with > `warning_days` remaining.
   - Domain expiration > `warning_days` remaining (or unconfirmed).
   - No hosting suspension signatures detected.
2. **`WARNING`**:
   - Website is accessible, but SSL certificate or domain expiration is within `warning_days` (default 30 days).
   - Expected HTML content type was not returned (e.g. API JSON or empty response).
3. **`DOWN`**:
   - DNS resolution failure, connection timeout, connection refused, or HTTP status >= 400.
4. **`POTENTIAL_EXPIRATION`**:
   - SSL certificate or domain registration has expired (`days_remaining < 0`).
   - Page content contains verified hosting suspension or resource exhaustion keywords (`detect_hosting_indicators()`).
5. **`UNABLE_TO_VERIFY`**:
   - Malformed URL or non-resolvable domain without clear classification.

> **CRITICAL RULE**: Never classify a site as expired hosting solely because it is unreachable or returns a server error. Hosting subscription payments are private; the tool must only flag `POTENTIAL_EXPIRATION` if there is explicit textual or expiration date evidence.

---

## 5. Domain Expiration Resolution Strategy

### Why RDAP alone is insufficient
- **RDAP** (`https://rdap.org/domain/<domain>`) is the modern REST standard for domain registration data registered with ICANN/IANA.
- While gTLDs (`.com`, `.net`, `.xyz`, etc.) support RDAP reliably, many **Country-Code Top-Level Domains (ccTLDs)** (such as `.bd`, `.com.bd`, `.gov.bd`) do **not** publish RDAP endpoints in the IANA bootstrap registry, returning HTTP 404.
- In addition, some ccTLD registries do not run public port-43 WHOIS daemons on standard root servers, requiring specific regional servers (e.g., `whois.get.bd` for Bangladesh).

### Multi-Tier Resolution Pattern
When checking domain expiration:
1. **Tier 1 (RDAP)**: Query `https://rdap.org/domain/{domain}`. If HTTP 200 and expiration event found, return result.
2. **Tier 2 (Targeted WHOIS Fallback)**:
   - If RDAP returns 404, unavailable, or lacks expiration data, inspect domain TLD.
   - For `.bd` domains (`.bd`, `.com.bd`, `.org.bd`, etc.), query `whois.get.bd` on port 43.
   - Parse registry date formats (such as `DD/MM/YYYY` or ISO `YYYY-MM-DD`).
3. **Tier 3 (Generic WHOIS / IANA Referral)**:
   - Query `whois.iana.org:43` to detect referral WHOIS servers for other ccTLDs.
4. **Graceful Fallback**:
   - If public expiration dates cannot be resolved, return status `UNAVAILABLE` or `NO_EXPIRATION_DATA` with clear registrar verification advice rather than crashing or asserting a false expiration.

---

## 6. Coding Standards & Conventions

1. **Modularity & Single-File Simplicity**:
   - `website_monitor.py` is currently kept self-contained for easy distribution and scheduled execution on headless servers. Keep helper functions focused and type-annotated (`dataclasses`, `tuple`, `datetime | None`).
2. **Defensive Error Handling**:
   - Each website audit is isolated inside `check_website()` with comprehensive `try...except` guards.
   - A network error, DNS timeout, or malformed certificate on one site **must never** terminate the batch.
3. **Logging**:
   - Use the configured `logging.getLogger("website_monitor")`.
   - Never print raw stack traces to console during standard batch runs; log detailed diagnostics to `logs/website_monitor.log`.
4. **Report Integrity**:
   - Report dates format as UTC (`%Y-%m-%d %H:%M UTC`).
   - Filenames use the format `website_report_YYYY-MM-DD.html` and `.csv`.
   - When multiple runs occur in one day without overwriting, append a timestamp `website_report_YYYY-MM-DD_HHMMSS`.
5. **Preserve Existing Documentation**:
   - Keep all docstrings, comments, and alerts in `README.md` and `website_monitor.py` intact when modifying neighboring code.

