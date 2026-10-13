import hashlib
import hmac
import io
import json
import tempfile
import time
import unittest
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

from rfid_backend.__main__ import ApiError, Handler, SCHEMA, authenticate, commit, database, preview, save_state, get_state


STUDENT = "A1B2C3D4"
OTHER_STUDENT = "11223344"
ITEM = "01020304"


class BackendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = database(str(Path(self.tmp.name) / "test.sqlite3"))
        self.conn.executescript(SCHEMA)
        self.conn.execute("INSERT INTO devices(id,secret) VALUES(?,?)", ("scanner-1", "ab" * 32))
        self.conn.executemany("INSERT INTO students(uid,name) VALUES(?,?)", [(STUDENT, "Alice"), (OTHER_STUDENT, "Bob")])
        self.conn.execute("INSERT INTO items(uid,name) VALUES(?,?)", (ITEM, "Book"))

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def signed_headers(self, body, nonce="01" * 16, path="/api/v1/preview", secret="ab" * 32):
        raw = json.dumps(body, separators=(",", ":")).encode()
        timestamp = str(int(time.time()))
        signing = f"POST\n{path}\n{timestamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}"
        return raw, {
            "X-Device-Id": "scanner-1",
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": hmac.new(bytes.fromhex(secret), signing.encode(), hashlib.sha256).hexdigest(),
        }

    def test_authentication_rejects_tamper_replay_and_revocation(self):
        body = {"mode": "borrow", "student_uid": STUDENT, "item_uid": None}
        raw, headers = self.signed_headers(body)
        self.assertEqual(authenticate(self.conn, "POST", "/api/v1/preview", headers, raw), "scanner-1")
        with self.assertRaisesRegex(ApiError, "already received"):
            authenticate(self.conn, "POST", "/api/v1/preview", headers, raw)
        raw, headers = self.signed_headers(body, nonce="02" * 16)
        with self.assertRaisesRegex(ApiError, "Invalid device credentials"):
            authenticate(self.conn, "POST", "/api/v1/preview", headers, raw + b" ")
        self.conn.execute("UPDATE devices SET active=0 WHERE id='scanner-1'")
        with self.assertRaisesRegex(ApiError, "Invalid device credentials"):
            authenticate(self.conn, "POST", "/api/v1/preview", headers, raw)

    def test_borrow_return_and_idempotent_confirmation(self):
        base = {"mode": "borrow", "student_uid": STUDENT, "item_uid": ITEM}
        self.assertEqual(preview(self.conn, base)["next"], "confirm")
        borrow = {**base, "request_id": "03" * 16}
        first = commit(self.conn, "scanner-1", borrow)
        self.assertEqual(first, commit(self.conn, "scanner-1", borrow))
        self.assertEqual(self.conn.execute("SELECT count(*) FROM loans").fetchone()[0], 1)
        with self.assertRaisesRegex(ApiError, "already borrowed"):
            preview(self.conn, base)
        with self.assertRaisesRegex(ApiError, "No active loan"):
            preview(self.conn, {"mode": "return", "student_uid": OTHER_STUDENT, "item_uid": ITEM})
        returned = commit(self.conn, "scanner-1", {"mode": "return", "student_uid": STUDENT, "item_uid": ITEM, "request_id": "04" * 16})
        self.assertTrue(returned["ok"])
        self.assertIsNotNone(self.conn.execute("SELECT returned_at FROM loans").fetchone()[0])
        self.assertEqual(preview(self.conn, base)["next"], "confirm")

    def test_reused_request_id_cannot_change_action(self):
        borrow = {"mode": "borrow", "student_uid": STUDENT, "item_uid": ITEM, "request_id": "05" * 16}
        commit(self.conn, "scanner-1", borrow)
        with self.assertRaisesRegex(ApiError, "different data"):
            commit(self.conn, "scanner-1", {**borrow, "mode": "return"})

    def test_unregistered_cards_are_rejected(self):
        with self.assertRaisesRegex(ApiError, "Student ID"):
            preview(self.conn, {"mode": "borrow", "student_uid": "ABCDEF12", "item_uid": None})
        with self.assertRaisesRegex(ApiError, "Item tag"):
            preview(self.conn, {"mode": "borrow", "student_uid": STUDENT, "item_uid": "ABCDEF12"})

    def test_device_state_follows_scan_sequence(self):
        self.assertEqual(get_state(self.conn, "scanner-1")["stage"], "idle")
        for stage in ("scan_student", "scan_item", "confirm", "success", "idle"):
            self.assertTrue(save_state(self.conn, "scanner-1", {"mode": "return", "stage": stage})["ok"])
            state = get_state(self.conn, "scanner-1")
            self.assertEqual((state["mode"], state["stage"]), ("return", stage))
            self.assertGreater(state["updated_at"], 0)
            self.assertNotIn("student_uid", state)
        with self.assertRaisesRegex(ApiError, "Invalid device mode or stage"):
            save_state(self.conn, "scanner-1", {"mode": "return", "stage": "made_up"})
        self.conn.execute("UPDATE devices SET active=0 WHERE id='scanner-1'")
        with self.assertRaisesRegex(ApiError, "Device not found"):
            get_state(self.conn, "scanner-1")

    def test_http_state_routes(self):
        body = {"mode": "borrow", "stage": "scan_student"}
        raw, signed = self.signed_headers(body, path="/api/v1/state")

        def handler(path):
            request = object.__new__(Handler)
            request.path = path
            request.server = SimpleNamespace(db_path=str(Path(self.tmp.name) / "test.sqlite3"))
            request.headers = Message()
            for key, value in signed.items():
                request.headers[key] = value
            request.headers["Content-Length"] = str(len(raw))
            request.rfile = io.BytesIO(raw)
            request.wfile = io.BytesIO()
            status = []
            request.send_response = lambda code: status.append(code)
            request.send_header = lambda *_: None
            request.end_headers = lambda: None
            return request, status

        request, status = handler("/api/v1/state")
        request.do_POST()
        self.assertEqual((status[0], json.loads(request.wfile.getvalue())["ok"]), (200, True))
        request, status = handler("/api/v1/state?device_id=scanner-1")
        request.do_GET()
        self.assertEqual((status[0], json.loads(request.wfile.getvalue())["stage"]), (200, "scan_student"))

    def test_http_route_uses_signed_request(self):
        body = {"mode": "borrow", "student_uid": STUDENT, "item_uid": None}
        raw, signed = self.signed_headers(body)

        def call_handler():
            handler = object.__new__(Handler)
            handler.path = "/api/v1/preview"
            handler.server = SimpleNamespace(db_path=str(Path(self.tmp.name) / "test.sqlite3"))
            handler.headers = Message()
            for key, value in signed.items():
                handler.headers[key] = value
            handler.headers["Content-Length"] = str(len(raw))
            handler.rfile = io.BytesIO(raw)
            handler.wfile = io.BytesIO()
            status = []
            handler.send_response = lambda code: status.append(code)
            handler.send_header = lambda *_: None
            handler.end_headers = lambda: None
            handler.do_POST()
            return status[0], json.loads(handler.wfile.getvalue())

        status, result = call_handler()
        self.assertEqual((status, result["next"]), (200, "scan_item"))
        status, result = call_handler()
        self.assertEqual((status, result["code"]), (401, "replay"))


if __name__ == "__main__":
    unittest.main()

