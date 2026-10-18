"""Forward ESP32 USB serial requests to the signed RFID HTTPS API."""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


PREFIX = b"@RFID:"
ROUTES = {"/api/v1/state", "/api/v1/preview", "/api/v1/commit"}
ID_PATTERN = re.compile(r"[0-9a-f]{16}\Z")


def signed_request(base_url, device_id, secret, path, body):
    """Send one request; return (HTTP status, JSON object)."""
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    signing = f"POST\n{path}\n{timestamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}"
    signature = hmac.new(secret, signing.encode(), hashlib.sha256).hexdigest()
    request = Request(
        base_url + path,
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Device-Id": device_id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature,
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=8) as response:
            try:
                return response.status, json.load(response)
            except (ValueError, UnicodeDecodeError):
                return 502, {"ok": False, "message": "Invalid API response"}
    except HTTPError as error:
        try:
            return error.code, json.load(error)
        except (ValueError, UnicodeDecodeError):
            return error.code, {"ok": False, "message": "Invalid API error response"}
    except (URLError, TimeoutError, OSError) as error:
        print(f"API connection failed: {error}", file=sys.stderr)
        return 503, {"ok": False, "code": "api_unreachable", "message": "Laptop cannot reach API"}


def process_frame(line, send):
    """Handle a single protocol frame, including validation before forwarding."""
    if not line.startswith(PREFIX):
        print(line.decode("utf-8", errors="replace").rstrip())
        return None
    try:
        frame = json.loads(line[len(PREFIX):])
    except (ValueError, UnicodeDecodeError):
        print("Ignored malformed scanner frame", file=sys.stderr)
        return None
    if not isinstance(frame, dict):
        return None
    request_id = frame.get("id")
    if not isinstance(request_id, str) or not ID_PATTERN.fullmatch(request_id):
        return None
    path = frame.get("path")
    body = frame.get("body")
    if not isinstance(path, str) or path not in ROUTES or not isinstance(body, dict):
        status, result = 400, {"ok": False, "message": "Invalid scanner request"}
    else:
        status, result = send(path, body)
        if not isinstance(result, dict):
            status, result = 502, {"ok": False, "message": "Invalid API response"}
        print(f"{path}: HTTP {status}", file=sys.stderr)
    reply = {"id": request_id, "status": status, "body": result}
    return PREFIX + json.dumps(reply, separators=(",", ":")).encode() + b"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="USB serial port, e.g. /dev/ttyUSB0 or COM3")
    parser.add_argument("--api-base-url", default=os.getenv("RFID_API_BASE_URL", ""))
    parser.add_argument("--device-id", default=os.getenv("RFID_DEVICE_ID", ""))
    args = parser.parse_args()
    secret_hex = os.getenv("RFID_DEVICE_SECRET_HEX", "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", secret_hex):
        parser.error("RFID_DEVICE_SECRET_HEX must contain 64 hex characters")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.device_id):
        parser.error("RFID_DEVICE_ID must be 1-64 letters, digits, hyphens, or underscores")
    url = urlsplit(args.api_base_url)
    if url.scheme != "https" or not url.netloc or url.query or url.fragment:
        parser.error("RFID_API_BASE_URL must be an HTTPS URL without query or fragment")
    try:
        import serial
    except ImportError:
        parser.error("Install pyserial first: python3 -m pip install pyserial")
    send = lambda path, body: signed_request(
        args.api_base_url.rstrip("/"), args.device_id, bytes.fromhex(secret_hex), path, body
    )
    try:
        with serial.Serial(args.port, 115200, timeout=1) as device:
            print(f"Bridge listening on {args.port}", file=sys.stderr)
            while True:
                line = device.read_until(b"\n", size=4096)
                if not line:
                    continue
                if len(line) >= 4096 or not line.endswith(b"\n"):
                    print("Ignored oversized or incomplete serial line", file=sys.stderr)
                    continue
                reply = process_frame(line, send)
                if reply is not None:
                    device.write(reply)
    except KeyboardInterrupt:
        return
    except serial.SerialException as error:
        parser.exit(1, f"Serial port error: {error}\n")


if __name__ == "__main__":
    main()
