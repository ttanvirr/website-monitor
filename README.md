# Daily Website Availability and Hosting Monitor

A small Python command-line tool that checks a list of website homepages and creates dated CSV and HTML reports. It checks HTTP availability, redirects, expected HTML content, DNS resolution, public RDAP domain-expiration data, SSL certificate validity/expiry, and common hosting-suspension/expiration page messages.

> **Important limitation:** This tool cannot confirm whether a hosting invoice has been paid or whether a hosting subscription is active. That information is normally private to the hosting provider's customer account. The script reports public evidence and indicators only; a failed website is not automatically classified as an expired hosting account.

## Project structure

```text
website-monitor/
├── data/
│   └── urls.txt
├── reports/                 # Generated CSV and HTML reports
├── logs/                    # Rotating execution log
├── tests/
│   └── test_website_monitor.py
├── website_monitor.py
├── requirements.txt
└── README.md
```

## 1. Requirements

- Python 3.10 or newer (the script uses standard-library features available in modern Python 3).
- Internet access for the websites, RDAP service, and HTTPS certificate endpoints.

The dependencies are `requests` (HTTP/RDAP requests) and `cryptography` (reading the date from a certificate that fails normal TLS verification). All other functionality uses the Python standard library.

## 2. Install

Open a terminal in the `website-monitor` project directory.

### Linux / WSL

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If `python3 -m pip` is unavailable inside your Linux environment, install the venv/pip package for your distribution first, then recreate the environment. On Ubuntu, for example:

```bash
sudo apt update
sudo apt install python3-venv python3-pip
```

### Windows PowerShell

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can skip activation and call the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 3. Add websites

Edit `data/urls.txt`. Add one website per line. A scheme is optional; the script assumes HTTPS if it is omitted.

```text
# Company websites
https://example.com
www.example.org
http://legacy.example.net
```

Blank lines and lines beginning with `#` are ignored. You do not need to edit the Python script when the list changes.

## 4. Run manually

From the project directory:

### Linux / WSL

```bash
.venv/bin/python website_monitor.py
```

### Windows PowerShell

```powershell
.\.venv\Scripts\python.exe .\website_monitor.py
```

The script creates these folders when necessary:

- `reports/website_report_YYYY-MM-DD.csv`
- `reports/website_report_YYYY-MM-DD.html`
- `logs/website_monitor.log`

If a report for the same date already exists, the next run uses a timestamp suffix so the earlier report is preserved. The CSV is UTF-8 with a byte-order mark for better compatibility with desktop spreadsheet applications.

### Optional command-line settings

```bash
python website_monitor.py --connect-timeout 8 --read-timeout 20 --warning-days 45
```

You can also supply alternate paths:

```bash
python website_monitor.py --urls-file data/urls.txt --reports-dir reports --logs-dir logs
```

Timeout values are in seconds. `--warning-days` controls when domain and SSL expiration are flagged as approaching.

## 5. Schedule it every morning

The script itself does not contain a schedule. Use your operating system's scheduler so you can change the run time without editing Python.

### Windows Task Scheduler (native Windows Python)

This is the simplest option if the project is stored on the Windows filesystem and Windows Python is installed.

1. Open **Task Scheduler** from the Windows Start menu.
2. Select **Create Basic Task** and name it `Daily Website Monitor`.
3. Choose **Daily**, then choose the morning time (for example, 8:00 AM).
4. Choose **Start a program**.
5. Set **Program/script** to the full path of the virtual environment's Python executable, for example:

   ```text
   C:\Users\YOUR_USER\website-monitor\.venv\Scripts\python.exe
   ```

6. Set **Add arguments** to:

   ```text
   website_monitor.py
   ```

7. Set **Start in** to the project directory, for example:

   ```text
   C:\Users\YOUR_USER\website-monitor
   ```

8. Finish. Open the task's **Properties** and use **Run** to test it. Check the `reports` and `logs` folders afterward.

Replace `YOUR_USER` with the actual Windows account folder and use the real project path. The computer must be powered on and awake at the scheduled time. If it is asleep, configure the task's **Conditions → Wake the computer to run this task** option where supported.

### Windows Task Scheduler (project inside WSL)

If the project lives in WSL, Task Scheduler can launch the WSL distribution. First, in PowerShell, find the distribution name:

```powershell
wsl.exe --list --quiet
```

Then create a daily task with:

- **Program/script:** `C:\Windows\System32\wsl.exe`
- **Add arguments:** (replace `Ubuntu` and the Linux path as needed)

  ```text
  -d Ubuntu --exec /bin/bash -lc "cd /home/YOUR_LINUX_USER/website-monitor && /home/YOUR_LINUX_USER/website-monitor/.venv/bin/python website_monitor.py"
  ```

- **Start in:** leave blank.

The task launches WSL when it runs, so WSL does not need to be left open beforehand. The Windows computer must still be powered on and awake. For a reliable scheduled run, configure the task to run under the same Windows user account that owns the WSL distribution; test it with **Run** and check the WSL project's report and log folders.

### Linux cron (optional)

Use the absolute project and virtual-environment paths. For example, to run at 8:00 AM every day:

```cron
0 8 * * * cd /home/YOUR_LINUX_USER/website-monitor && /home/YOUR_LINUX_USER/website-monitor/.venv/bin/python website_monitor.py >> /home/YOUR_LINUX_USER/website-monitor/logs/cron.log 2>&1
```

Edit your crontab with `crontab -e`. Cron uses the machine's configured timezone. For WSL, cron is not necessarily running whenever Windows starts; use Windows Task Scheduler to launch WSL if you need a dependable Windows-managed schedule.

## 6. Understanding the report

The HTML report is intended for quick review. The CSV contains the same key fields in a spreadsheet-friendly format.

| Final status | Meaning |
|---|---|
| `WORKING` | Homepage is reachable, returns an identified HTML response, and no significant checked issue was found. |
| `WARNING` | Homepage responds, but an issue needs attention (for example, HTTP 4xx, use of HTTP without HTTPS, certificate trouble, an approaching expiration, or a resource-limit page). |
| `DOWN` | A connection/DNS/timeout problem or an HTTP 5xx server error prevented a normal check. |
| `POTENTIAL_EXPIRATION` | Public RDAP data says the domain expiration date has passed, or the page contains a specific domain/hosting suspension or expiration indicator. Confirm with the provider. |
| `UNABLE_TO_VERIFY` | The URL is invalid or the check could not establish enough information to classify the website. |

Component fields provide more detail:

- **HTTP status:** Status code from the final response after redirects.
- **Availability:** Whether the HTTP request completed, returned an error, timed out, or failed TLS verification.
- **Domain expiration:** Expiration event published by the domain registry through RDAP. Some registries do not publish it.
- **SSL status:** `VALID`, `EXPIRES_SOON`, `EXPIRED`, `INVALID_OR_UNTRUSTED`, `CHECK_FAILED`, or `NOT_APPLICABLE`.
- **DNS status / resolved IPs:** Whether the machine running the script resolved the hostname and which addresses it returned.
- **IP network RDAP:** Public registration information for the first resolved public IP, when available. This may identify an ISP, CDN, or network operator; it is not necessarily the website's hosting provider or origin server. Results are cached within one run when multiple sites share an IP.
- **Hosting indicators:** Specific phrases detected in the homepage body. These are clues, not proof of an expired hosting plan.

## 7. Tests

Run the automated tests from the project directory:

```bash
python -m unittest discover -s tests -v
```

The tests mock network dependencies, so they do not require real websites to be down. They cover URL validation, RDAP date parsing, hosting-page phrase detection, SSL error handling, website-check error isolation, successful HTML responses, server errors, URL-list parsing, and CSV/HTML report generation without overwriting prior reports.

## 8. What this tool cannot verify

- Whether a hosting bill was paid, an invoice is overdue, or a hosting package was renewed.
- Whether the website's database, login, checkout, forms, or other private application features work correctly. This tool performs a light homepage check only.
- Domain expiration when the registry does not publish an expiration event in RDAP.
- The true hosting provider/origin from an IP network registration record. A CDN or reverse proxy (for example, a DNS proxy) may be the visible network instead of the origin host.
- Website availability from every country or network. The result reflects the network where the script runs.
- Whether a third-party outage is affecting all visitors. A `DOWN` result should be checked from another network or monitoring service before escalating.

For actual hosting subscription status, check the hosting provider's billing/control panel or ask the provider. For application-level checks, add explicit, safe health-check URLs supplied by the website owner rather than crawling the entire site.
