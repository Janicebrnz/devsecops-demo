import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app


class FunctionalTests(unittest.TestCase):
    def setUp(self):
        self.conn = app.init_db()

    def test_login_ok(self):
        self.assertTrue(app.login(self.conn, "alice", "pass1"))

    def test_login_wrong_password(self):
        self.assertFalse(app.login(self.conn, "alice", "nope"))

    def test_find_user(self):
        self.assertEqual(app.find_user(self.conn, "bob")[1], "bob")

    def test_parse_settings_literal(self):
        self.assertEqual(app.parse_settings("{'theme': 'dark'}"), {"theme": "dark"})


class SecurityRegressionTests(unittest.TestCase):
    """These FAIL on the vulnerable code and PASS after remediation."""
    def setUp(self):
        self.conn = app.init_db()

    def test_sqli_find_user(self):
        self.assertIsNone(app.find_user(self.conn, "' OR '1'='1"))

    def test_sqli_login_bypass(self):
        self.assertFalse(app.login(self.conn, "alice' --", "anything"))

    def test_no_code_execution_via_settings(self):
        with self.assertRaises(ValueError):
            app.parse_settings("__import__('os').getcwd()")

    def test_no_hardcoded_secret(self):
        self.assertNotEqual(app.API_KEY, "sk_live_51H8exampleSECRETkey")


if __name__ == "__main__":
    unittest.main()
