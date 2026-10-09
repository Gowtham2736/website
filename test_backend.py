import json
import threading
import unittest
import uuid
from http.client import HTTPConnection

import server


class BackendApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.initialize_database()
        cls.server = server.ThreadingHTTPServer(("127.0.0.1", 0), server.StoreHandler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.host, cls.port = cls.server.server_address

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        server.RATE_LIMIT_BUCKETS.clear()
        self.cookies = []

    def request(self, method, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        connection = HTTPConnection(self.host, self.port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(self.cookies)
        if body is not None:
            headers["Content-Length"] = str(len(body))
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        set_cookie = response.headers.get("Set-Cookie")
        if set_cookie:
            cookie_name, _, cookie_value = set_cookie.partition("=")
            self.cookies = [value for value in self.cookies if not value.startswith(f"{cookie_name}=")]
            self.cookies.append(f"{cookie_name}={cookie_value.split(';', 1)[0]}")
        data = response.read().decode("utf-8")
        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            parsed = {"raw": data}
        return response.status, parsed

    def test_registration_and_login_work(self):
        email = f"{uuid.uuid4().hex[:8]}@example.com"
        status, auth = self.request(
            "POST",
            "/api/register",
            {"name": "Alice Reader", "email": email, "password": "supersecret1"},
        )
        self.assertEqual(status, 201, auth)
        self.assertEqual(auth["user"]["email"], email)

        status, me = self.request("GET", "/api/me")
        self.assertEqual(status, 200, me)
        self.assertIsNotNone(me["user"])
        self.assertEqual(me["user"]["email_verified"], 0)

    def test_email_verification_and_password_reset_work(self):
        email = f"{uuid.uuid4().hex[:8]}@example.com"
        status, register = self.request(
            "POST",
            "/api/register",
            {"name": "Reset User", "email": email, "password": "newpassword1"},
        )
        self.assertEqual(status, 201, register)
        token = register["verification_token"]

        status, verified = self.request("POST", "/api/verify-email", {"token": token})
        self.assertEqual(status, 200, verified)

        status, reset = self.request("POST", "/api/request-password-reset", {"email": email})
        self.assertEqual(status, 200, reset)
        reset_token = reset["reset_token"]

        status, changed = self.request(
            "POST",
            "/api/reset-password",
            {"token": reset_token, "password": "newpassword2"},
        )
        self.assertEqual(status, 200, changed)

    def test_login_rate_limit_blocks_repeated_attempts(self):
        email = f"{uuid.uuid4().hex[:8]}@example.com"
        for _ in range(6):
            status, response = self.request(
                "POST",
                "/api/login",
                {"email": email, "password": "wrong-password"},
            )
            if status == 429:
                self.assertIn("Too many requests", response.get("error", ""))
                return
        self.fail("Expected a rate limit response after repeated login attempts.")


if __name__ == "__main__":
    unittest.main()
