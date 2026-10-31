#!/usr/bin/env python3
"""Security scanner for checking HTTP/HTTPS site headers and cookie flags."""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

import requests

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "X-XSS-Protection",
]


def normalize_url(raw_url: str) -> str:
    """Ensure a scheme is present for the target URL."""
    url = raw_url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
    if "://" not in url:
        url = f"https://{url}"
    return url


def get_header_value(headers: requests.structures.CaseInsensitiveDict, name: str) -> Optional[str]:
    return headers.get(name)


def parse_set_cookie_value(raw_cookie: str) -> Dict[str, object]:
    """Parse a Set-Cookie header into a dictionary with common cookie flags."""
    cookie_data: Dict[str, object] = {
        "name": "",
        "value": "",
        "secure": False,
        "httponly": False,
        "samesite": "None",
    }

    if not raw_cookie:
        return cookie_data

    parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
    if not parts:
        return cookie_data

    name_value = parts[0]
    if "=" not in name_value:
        return cookie_data

    name, value = name_value.split("=", 1)
    cookie_data["name"] = name.strip()
    cookie_data["value"] = value.strip()

    for part in parts[1:]:
        key, _, val = part.partition("=")
        key_lower = key.strip().lower()
        if key_lower == "secure":
            cookie_data["secure"] = True
        elif key_lower == "httponly":
            cookie_data["httponly"] = True
        elif key_lower == "samesite":
            cookie_data["samesite"] = (val or "None").strip() or "None"

    return cookie_data


def analyze_cookie_flags(response: requests.Response) -> List[str]:
    """Extract cookie names and flag information from a response."""
    cookie_rows: List[str] = []

    set_cookie_headers = []
    try:
        set_cookie_headers = response.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw_cookie = response.headers.get("Set-Cookie")
        if raw_cookie:
            set_cookie_headers = [raw_cookie]

    parsed_cookies = []
    for raw_cookie in set_cookie_headers:
        parsed = parse_set_cookie_value(raw_cookie)
        if parsed.get("name"):
            parsed_cookies.append(parsed)

    if not parsed_cookies and response.cookies:
        for cookie in response.cookies:
            parsed_cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                    "samesite": cookie._rest.get("SameSite", "None") if hasattr(cookie, "_rest") else "None",
                }
            )

    if not parsed_cookies:
        return ["No cookies found."]

    for cookie in parsed_cookies:
        samesite = cookie.get("samesite", "None")
        cookie_rows.append(
            f"- {cookie.get('name', 'unknown')}: HttpOnly={str(cookie.get('httponly', False))}, "
            f"Secure={str(cookie.get('secure', False))}, SameSite={samesite}"
        )
    return cookie_rows


def check_security_headers(response: requests.Response) -> List[str]:
    """Check for presence of security headers and return human-readable results."""
    results: List[str] = []
    headers = response.headers

    for header in SECURITY_HEADERS:
        header_value = get_header_value(headers, header)
        status = "Present" if header_value is not None else "Missing"
        results.append(f"- {header}: {status}")

    return results


def run_scan(target_url: str, timeout: int = 10) -> int:
    url = normalize_url(target_url)
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"Error fetching {url}: {exc}", file=sys.stderr)
        return 1

    print(f"Checking: {response.url}\n")
    print("Security Headers:")
    for item in check_security_headers(response):
        print(item)

    print("\nCookies:")
    for item in analyze_cookie_flags(response):
        print(item)

    print()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a URL for security headers and cookie flags."
    )
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    return run_scan(args.url, timeout=args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())