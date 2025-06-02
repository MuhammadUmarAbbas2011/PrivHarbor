# PrivHarbor

A comprehensive security platform that offers:

- **URL Phishing Detection** (via heuristics & VirusTotal)
- **File Malware Scanning** (using VirusTotal’s API)
- **Domain Reputation Lookup** (VirusTotal-based)
- **Advanced URL-Heuristic Scanner** (checks for character-substitution, suspicious TLDs, shortened URLs, etc.)
- **Browser Extension** that automatically blocks malicious cookies

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
  - [Advanced URL Security Scanner (Standalone)](#advanced-url-security-scanner-standalone)
  - [Browser Extension](#browser-extension)
- [Dependencies](#dependencies)
- [License](#license)

## Project Overview

PrivHarbor is a security‐focused Django/DRF application and accompanying browser extension designed to help developers and end users quickly identify phishing URLs, scan uploaded files for malware, retrieve domain reputation data, and automatically block malicious cookies in real-time.

By leveraging a mix of heuristic checks and the VirusTotal public API, PrivHarbor aims to provide an open‐source, plug-and-play platform for threat intelligence and proactive protection.

## Features

**Phishing URL Detection (APIView)**

- Heuristic analysis (character substitution, spoofed subdomains, suspicious keywords/TLDs).
- Integration with an `AdvancedURLSecurityScanner` class for a full “risk score” assessment.

**File Malware Scanning (APIView)**

- Upload any file; PrivHarbor pushes it to VirusTotal for deep scanning.
- Returns engine-by-engine breakdown of malicious detections.

**Domain Reputation Lookup (APIView)**

- Fetches VirusTotal’s reputation and analysis stats for a queried domain.

**AdvancedURLSecurityScanner (Standalone Class)**

- Contains trusted-domain lists, suspicious TLDs, blacklisted keywords, character-substitution logic, DNS/whois lookups, and SSL checks.
- Calculates a “final risk score” and categorizes URLs as LOW/MEDIUM/HIGH risk.

**Browser Extension**

- Monitors outgoing cookies.
- Blocks cookies deemed “malicious” (matching known phishing or tracking patterns).

## Prerequisites

- Python 3.8+
- Django 3.2 or newer
- django-rest-framework 3.12+
- A valid VirusTotal API key (v3)
- A modern browser (Chrome/Firefox) to install the extension

## Installation

### Clone the Repository

```bash
git clone https://github.com/MuhammadUmarAbbas2011/PrivHarbor.git
cd PrivHarbor
```

### Create & Activate a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
venv\Scripts\activate     # Windows
```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Apply Migrations & Create Superuser

```bash
python manage.py migrate
python manage.py createsuperuser
```

### Run the Development Server

```bash
python manage.py runserver
```

### Load the Browser Extension

- Navigate to `chrome://extensions` or `about:addons` in Firefox.
- Enable “Developer Mode” (Chrome) or “Debug Mode” (Firefox).
- Click “Load unpacked” and select the `tracker-blocker/` folder.

## Configuration

### Set Your VirusTotal API Key

On macOS/Linux:

```bash
export VT_API_KEY="YOUR_VT_API_KEY_HERE"
```

On Windows (PowerShell):

```powershell
setx VT_API_KEY "YOUR_VT_API_KEY_HERE"
```

### Django Settings

In `settings.py`, ensure:

```python
INSTALLED_APPS = [
    'rest_framework',
    'coresec',
]
```

## Usage

Once the server is running at `http://127.0.0.1:8000/`, use the following endpoints.

## API Endpoints

### 1. Phishing Check

- **URL**: `POST 127.0.0.1:8000/api/coresec/phishing/check/

**Request Body**:

```json
{
  "url": "http://paypaaal.com/"
}
```

**Response**:

```json
{
  "is_safe": false,
  "reasons": [
    "Contains suspicious keywords: login, secure, verify",
    "URL does not use HTTPS",
    "Domain 'some-suspicious-site.com' is suspiciously similar to 'paypal.com'"
  ]
}
```

### 2. Malware Scan

- **URL**: `POST 127.0.0.1:8000/api/coresec//malware-scan/

**Request**:

- Content-Type: `multipart/form-data`
- Form field: `file`

**Response**:

```json
{
  "file_name": "example.exe",
  "malicious_count": 3,
  "total_engines": 72,
  "malicious_engines": {
    "EngineA": { "category": "malicious", "vote": {} },
    "EngineB": { "category": "malicious", "vote": {} },
    "EngineC": { "category": "malicious", "vote": {} }
  }
}
```

### 3. Domain Reputation

- **URL**: `GET http://localhost:8000/api/coresec/domain-reputation/?domain=example.com`

**Response**:

```json
{
  "domain": "example.com",
  "reputation": 15,
  "categories": {
    "ads": false,
    "phishing": true,
    "malware": false
  },
  "last_analysis_stats": {
    "harmless": 68,
    "malicious": 2,
    "suspicious": 1,
    "undetected": 70,
    "timeout": 0
  }
}
```

## Advanced URL Security Scanner (Standalone)

```python
from phishing_checker import AdvancedURLSecurityScanner

scanner = AdvancedURLSecurityScanner(url="http://some-phishy-domain.tk/login-verify")
report_json = scanner.run_full_scan()
print(report_json)
```

**Checks performed**:

- HTTPS usage
- Suspicious TLDs (.zip, .xyz, .tk)
- Character substitution (e.g., pàypāl.com)
- Shortened URLs (bit.ly)
- Excessive hyphens or length
- Mixed Unicode/punycode

## Browser Extension

- Monitors HTTP requests cookies.
- Blocks cookies based.

### Installation

- Go to browser extension/debug page.
- Enable Developer Mode.
- Load the `tracker-blocker/` directory.

## Dependencies

```text
Django>=3.2
djangorestframework>=3.12
requests>=2.25
cryptography>=3.4
dnspython>=2.0
python-whois>=0.7
```

## License

PrivHarbor is released under the MIT License.
