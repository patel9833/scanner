# Scanner

Security scanner for checking HTTP/HTTPS site headers and cookie flags.

This project helps you analyze a website by checking whether important security headers are present and whether cookies are configured with secure flags.

## Features
- Checks HTTP/HTTPS response headers
- Detects common security headers such as `Strict-Transport-Security`, `X-Frame-Options`, `Content-Security-Policy`, and more
- Reviews cookie flags including `Secure`, `HttpOnly`, and `SameSite`
- Can be used from the command line for quick audits

## Prerequisites
Before installing the project, make sure you have:

- Python 3.9 or newer
- `pip` package manager
- Git
- A terminal or command prompt

## Step-by-step installation

### 1. Clone the repository

```bash
git clone https://github.com/patel9833/scanner.git
cd scanner
```

### 2. Create a virtual environment

On Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On Windows (Command Prompt):

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 3. Upgrade pip

```bash
python -m pip install --upgrade pip
```

### 4. Install dependencies

If the project includes a `requirements.txt` file, install it with:

```bash
pip install -r requirements.txt
```

If no dependency file is present yet, install the main packages manually:

```bash
pip install requests
```

### 5. Verify installation

```bash
python --version
pip list
```

If the project has a script entry point, you can test it with:

```bash
python app.py --help
```

or:

```bash
python scanner.py --help
```

## Usage

Example usage:

```bash
python scanner.py https://example.com
```

You can also pass a URL with or without `https://` depending on the script implementation.

## Example output

```text
Checking: https://example.com

Security Headers:
- Strict-Transport-Security: Missing
- X-Frame-Options: Present
- Content-Security-Policy: Missing

Cookies:
- sessionid: HttpOnly=True, Secure=False, SameSite=Lax
```

## Troubleshooting

- If `python` is not recognized, use `python3` instead.
- If `pip` is not found, install Python from https://www.python.org and ensure it is added to PATH.
- If you get an error about missing dependencies, run:

```bash
pip install requests
```

## Contributing

Pull requests are welcome. Please keep changes organized and update this README if the setup process changes.

## License

This project does not currently include a license file. If you plan to publish it publicly, add a license such as MIT.
