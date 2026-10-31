# Scanner

Security scanner for checking HTTP/HTTPS site headers and cookie flags.

This project helps you analyze a website by checking whether important security headers are present and whether cookies are configured with secure flags.

## Features
- Checks HTTP/HTTPS response headers
- Detects common security headers such as `Strict-Transport-Security`, `X-Frame-Options`, `Content-Security-Policy`, and more
- Reviews cookie flags including `Secure`, `HttpOnly`, and `SameSite`
- Runs from the command line for quick audits

## Repository layout

The project includes a working Python implementation:

- `scanner.py` — main scanner logic
- `app.py` — convenience entry point
- `requirements.txt` — Python dependencies
- `.gitignore` — local environment files to ignore

## Prerequisites
Before installing the project, make sure you have:

- Python 3.9 or newer
- `pip` package manager
- Git
- A terminal or command prompt

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/patel9833/scanner.git
cd scanner