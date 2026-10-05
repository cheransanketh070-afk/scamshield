import io
import json
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout

from scamshield import cli
from scamshield.server import create_server


class CLI(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, buf.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_cli("check", "Lunch tomorrow at 1pm?")[0], 0)
        self.assertEqual(self.run_cli("check", "Work from home! Earn $300 per day")[0], 1)
        self.assertEqual(self.run_cli("check", "You have won the lottery, pay the processing fee")[0], 2)

    def test_json_output(self):
        code, out = self.run_cli("check", "--json", "Pay the processing fee now")
        self.assertIn("score", json.loads(out))

    def test_rules_command(self):
        code, out = self.run_cli("rules")
        self.assertEqual(code, 0)
        self.assertIn("rules loaded", out)


class API(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = create_server("127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def post(self, body: bytes):
        req = urllib.request.Request(self.base + "/api/analyze", data=body,
                                     headers={"Content-Type": "application/json"})
        return urllib.request.urlopen(req)

    def test_health(self):
        with urllib.request.urlopen(self.base + "/health") as r:
            self.assertEqual(json.load(r)["status"], "ok")

    def test_analyze(self):
        with self.post(json.dumps({"text": "Pay the redelivery fee at bit.ly/x"}).encode()) as r:
            self.assertEqual(json.load(r)["verdict"], "likely_scam")

    def test_bad_json_is_400(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.post(b"not json")
        self.assertEqual(cm.exception.code, 400)

    def test_oversized_body_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.post(b"x" * (70 * 1024))
        self.assertEqual(cm.exception.code, 413)

    def test_ui_is_served_with_security_headers(self):
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn(b"ScamShield", r.read())
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
