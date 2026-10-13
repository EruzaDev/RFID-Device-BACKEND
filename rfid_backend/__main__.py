import argparse
from contextlib import closing
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY, secret TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS students (
    uid TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS items (
    uid TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, student_uid TEXT NOT NULL,
    item_uid TEXT NOT NULL, borrowed_at INTEGER NOT NULL, returned_at INTEGER,
    borrow_device TEXT NOT NULL, return_device TEXT,
    FOREIGN KEY(student_uid) REFERENCES students(uid),
    FOREIGN KEY(item_uid) REFERENCES items(uid)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_loan_per_item
    ON loans(item_uid) WHERE returned_at IS NULL;
CREATE TABLE IF NOT EXISTS nonces (
    device_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
    PRIMARY KEY(device_id, nonce)
);
CREATE TABLE IF NOT EXISTS requests (
    device_id TEXT NOT NULL, request_id TEXT NOT NULL, body_hash TEXT NOT NULL,
    response TEXT NOT NULL, PRIMARY KEY(device_id, request_id)
);
CREATE TABLE IF NOT EXISTS device_state (
    device_id TEXT PRIMARY KEY, mode TEXT NOT NULL, stage TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);
"""
UID = re.compile(r"[0-9A-F]{8}(?:[0-9A-F]{6})?(?:[0-9A-F]{6})?\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
STAGES = {"idle", "scan_student", "scan_item", "confirm", "success", "error"}
STAGE_MESSAGES = {
    "idle": "Standby Monitor",
    "scan_student": "Tap Student ID",
    "scan_item": "Tap Equipment Tag",
    "confirm": "Await Confirmation",
    "success": "Transaction Complete",
    "error": "Transaction Not Accepted",
}


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def database(path):
    Path(path).touch(mode=0o600, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def valid_uid(value):
    if not isinstance(value, str) or not UID.fullmatch(value):
        raise ApiError(400, "bad_uid", "UID must be 4, 7, or 10 bytes of uppercase hex")
    return value


def fields(body, required):
    if not isinstance(body, dict) or set(body) != set(required):
        raise ApiError(400, "bad_body", "Unexpected or missing JSON fields")
    if body["mode"] not in ("borrow", "return"):
        raise ApiError(400, "bad_mode", "Mode must be borrow or return")
    valid_uid(body["student_uid"])
    if body["item_uid"] is not None:
        valid_uid(body["item_uid"])


def preview(conn, body):
    fields(body, ("mode", "student_uid", "item_uid"))
    student = conn.execute("SELECT name FROM students WHERE uid=? AND active=1", (body["student_uid"],)).fetchone()
    if student is None:
        raise ApiError(404, "student_unknown", "Student ID not registered or inactive")
    result = {"ok": True, "student_name": student["name"]}
    if body["item_uid"] is None:
        result["next"] = "scan_item"
        return result
    item = conn.execute("SELECT name FROM items WHERE uid=? AND active=1", (body["item_uid"],)).fetchone()
    if item is None:
        raise ApiError(404, "item_unknown", "Item tag not registered or inactive")
    loan = conn.execute("SELECT student_uid FROM loans WHERE item_uid=? AND returned_at IS NULL", (body["item_uid"],)).fetchone()
    if body["mode"] == "borrow" and loan is not None:
        raise ApiError(409, "already_borrowed", "Item is already borrowed")
    if body["mode"] == "return" and (loan is None or loan["student_uid"] != body["student_uid"]):
        raise ApiError(409, "wrong_borrower", "No active loan for this student and item")
    result.update(item_name=item["name"], next="confirm")
    return result


def commit(conn, device_id, body):
    fields(body, ("mode", "student_uid", "item_uid", "request_id"))
    if body["item_uid"] is None or not isinstance(body["request_id"], str) or not HEX32.fullmatch(body["request_id"]):
        raise ApiError(400, "bad_body", "Item UID and 32-character request ID are required")
    body_hash = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    conn.execute("BEGIN IMMEDIATE")
    try:
        previous = conn.execute("SELECT body_hash,response FROM requests WHERE device_id=? AND request_id=?", (device_id, body["request_id"])).fetchone()
        if previous:
            if previous["body_hash"] != body_hash:
                raise ApiError(409, "request_reused", "Request ID was used with different data")
            conn.execute("COMMIT")
            return json.loads(previous["response"])
        info = preview(conn, {key: body[key] for key in ("mode", "student_uid", "item_uid")})
        now = int(time.time())
        if body["mode"] == "borrow":
            conn.execute("INSERT INTO loans(student_uid,item_uid,borrowed_at,borrow_device) VALUES(?,?,?,?)", (body["student_uid"], body["item_uid"], now, device_id))
        else:
            updated = conn.execute("UPDATE loans SET returned_at=?,return_device=? WHERE item_uid=? AND student_uid=? AND returned_at IS NULL", (now, device_id, body["item_uid"], body["student_uid"]))
            if updated.rowcount != 1:
                raise ApiError(409, "wrong_borrower", "No active loan for this student and item")
        result = {"ok": True, "mode": body["mode"], "student_name": info["student_name"], "item_name": info["item_name"], "recorded_at": now}
        conn.execute("INSERT INTO requests(device_id,request_id,body_hash,response) VALUES(?,?,?,?)", (device_id, body["request_id"], body_hash, json.dumps(result)))
        conn.execute("COMMIT")
        return result
    except Exception:
        conn.execute("ROLLBACK")
        raise


def authenticate(conn, method, path, headers, raw):
    device_id = headers.get("X-Device-Id", "")
    timestamp = headers.get("X-Timestamp", "")
    nonce = headers.get("X-Nonce", "")
    signature = headers.get("X-Signature", "")
    if not TOKEN.fullmatch(device_id) or not timestamp.isascii() or not timestamp.isdecimal() or not HEX32.fullmatch(nonce) or not HEX64.fullmatch(signature):
        raise ApiError(401, "auth_failed", "Invalid device credentials")
    if abs(int(time.time()) - int(timestamp)) > 300:
        raise ApiError(401, "clock_skew", "Device clock differs by more than 5 minutes")
    device = conn.execute("SELECT secret FROM devices WHERE id=? AND active=1", (device_id,)).fetchone()
    if device is None:
        raise ApiError(401, "auth_failed", "Invalid device credentials")
    signing = f"{method}\n{path}\n{timestamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}"
    expected = hmac.new(bytes.fromhex(device["secret"]), signing.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ApiError(401, "auth_failed", "Invalid device credentials")
    try:
        conn.execute("INSERT INTO nonces(device_id,nonce,seen_at) VALUES(?,?,?)", (device_id, nonce, int(time.time())))
    except sqlite3.IntegrityError:
        raise ApiError(401, "replay", "Request was already received") from None
    conn.execute("DELETE FROM nonces WHERE seen_at < ?", (int(time.time()) - 600,))
    return device_id


def save_state(conn, device_id, body):
    if not isinstance(body, dict) or set(body) != {"mode", "stage"}:
        raise ApiError(400, "bad_body", "Mode and stage are required")
    if body["mode"] not in ("borrow", "return") or body["stage"] not in STAGES:
        raise ApiError(400, "bad_state", "Invalid device mode or stage")
    updated_at = int(time.time() * 1000)
    conn.execute("INSERT INTO device_state(device_id,mode,stage,updated_at) VALUES(?,?,?,?) "
                 "ON CONFLICT(device_id) DO UPDATE SET mode=excluded.mode,stage=excluded.stage,updated_at=excluded.updated_at",
                 (device_id, body["mode"], body["stage"], updated_at))
    return {"ok": True}


def get_state(conn, device_id):
    if not TOKEN.fullmatch(device_id):
        raise ApiError(400, "bad_device", "Invalid device ID")
    device = conn.execute("SELECT active FROM devices WHERE id=?", (device_id,)).fetchone()
    if device is None or not device["active"]:
        raise ApiError(404, "device_unknown", "Device not found")
    row = conn.execute("SELECT mode,stage,updated_at FROM device_state WHERE device_id=?", (device_id,)).fetchone()
    mode, stage, updated_at = (row["mode"], row["stage"], row["updated_at"]) if row else ("borrow", "idle", 0)
    return {"device_id": device_id, "mode": mode, "stage": stage,
            "message": STAGE_MESSAGES[stage], "updated_at": updated_at}


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        route = urlsplit(self.path)
        if route.path == "/api/v1/health" and not route.query:
            self.respond(200, {"ok": True})
        elif route.path == "/api/v1/state":
            try:
                params = parse_qs(route.query, strict_parsing=True)
                if set(params) != {"device_id"} or len(params["device_id"]) != 1:
                    raise ApiError(400, "bad_device", "One device ID is required")
                with closing(database(self.server.db_path)) as conn:
                    self.respond(200, get_state(conn, params["device_id"][0]))
            except (ApiError, ValueError) as exc:
                if isinstance(exc, ApiError):
                    self.respond(exc.status, {"ok": False, "code": exc.code, "message": exc.message})
                else:
                    self.respond(400, {"ok": False, "code": "bad_device", "message": "Invalid device ID"})
        else:
            self.respond(404, {"ok": False, "code": "not_found", "message": "Unknown route"})

    def do_POST(self):
        if self.path not in ("/api/v1/preview", "/api/v1/commit", "/api/v1/state"):
            self.respond(404, {"ok": False, "code": "not_found", "message": "Unknown route"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if not 1 <= length <= 1024:
                raise ApiError(400, "bad_body", "JSON body must be 1 to 1024 bytes")
            raw = self.rfile.read(length)
            with closing(database(self.server.db_path)) as conn:
                device_id = authenticate(conn, "POST", self.path, self.headers, raw)
                try:
                    body = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise ApiError(400, "bad_json", "Invalid JSON") from None
                if self.path.endswith("preview"):
                    result = preview(conn, body)
                elif self.path.endswith("commit"):
                    result = commit(conn, device_id, body)
                else:
                    result = save_state(conn, device_id, body)
            self.respond(200, result)
        except ApiError as exc:
            self.respond(exc.status, {"ok": False, "code": exc.code, "message": exc.message})
        except (ValueError, OverflowError):
            self.respond(400, {"ok": False, "code": "bad_request", "message": "Invalid request"})


def main():
    parser = argparse.ArgumentParser(description="RFID borrow/return backend")
    parser.add_argument("--db", default="rfid.sqlite3", help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8443)
    server.add_argument("--cert", required=True, help="TLS certificate PEM")
    server.add_argument("--key", required=True, help="TLS private key PEM")
    for name in ("student", "item"):
        command = sub.add_parser("add-" + name)
        command.add_argument("uid")
        command.add_argument("name")
        deactivate = sub.add_parser("disable-" + name)
        deactivate.add_argument("uid")
    device = sub.add_parser("add-device")
    device.add_argument("id")
    disable = sub.add_parser("disable-device")
    disable.add_argument("id")
    sub.add_parser("list-loans")
    args = parser.parse_args()
    path = str(Path(args.db).expanduser().resolve())
    with closing(database(path)) as conn:
        conn.executescript(SCHEMA)
        if args.command in ("add-student", "add-item"):
            table = "students" if args.command == "add-student" else "items"
            uid = valid_uid(args.uid.upper())
            if not args.name.strip():
                parser.error("Name cannot be empty")
            conn.execute(f"INSERT INTO {table}(uid,name,active) VALUES(?,?,1) ON CONFLICT(uid) DO UPDATE SET name=excluded.name,active=1", (uid, args.name.strip()))
            print(f"Saved {args.command[4:]} {uid}")
        elif args.command in ("disable-student", "disable-item"):
            table = "students" if args.command == "disable-student" else "items"
            uid = valid_uid(args.uid.upper())
            if conn.execute(f"UPDATE {table} SET active=0 WHERE uid=?", (uid,)).rowcount == 0:
                parser.error("UID not found")
            print(f"Disabled {uid}")
        elif args.command == "add-device":
            if not TOKEN.fullmatch(args.id):
                parser.error("Device ID must be 1 to 64 letters, digits, hyphens or underscores")
            secret = secrets.token_hex(32)
            conn.execute("INSERT INTO devices(id,secret) VALUES(?,?)", (args.id, secret))
            print(f"Device ID: {args.id}\nSecret hex (copy to ESP32 secrets.h once): {secret}")
        elif args.command == "disable-device":
            if conn.execute("UPDATE devices SET active=0 WHERE id=?", (args.id,)).rowcount == 0:
                parser.error("Device not found")
            print("Device disabled")
        elif args.command == "list-loans":
            rows = conn.execute("SELECT loans.id,students.name student,items.name item,borrowed_at,returned_at FROM loans JOIN students ON students.uid=student_uid JOIN items ON items.uid=item_uid ORDER BY loans.id DESC").fetchall()
            for row in rows:
                print(f"{row['id']}\t{row['student']}\t{row['item']}\t{row['borrowed_at']}\t{row['returned_at'] or 'OPEN'}")
    if args.command == "serve":
        httpd = ThreadingHTTPServer((args.host, args.port), Handler)
        httpd.db_path = path
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f"Serving HTTPS on {args.host}:{args.port}", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
