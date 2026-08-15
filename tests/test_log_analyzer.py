import unittest
import sys
from pathlib import Path

# Allow Python to find the src directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_DIR))

import log_analyzer


class TestLogAnalyzer(unittest.TestCase):

    def test_parse_successful_login(self):
        log = "2026-08-13 10:00:01 SUCCESS Login user=alice IP=192.168.1.10"

        result = log_analyzer.parse_log_entry(log)

        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["user"], "alice")
        self.assertEqual(result["ip"], "192.168.1.10")

    def test_parse_failed_login(self):
        log = "2026-08-13 10:01:01 FAILED Login user=root IP=45.33.21.10"

        result = log_analyzer.parse_log_entry(log)

        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["user"], "root")
        self.assertEqual(result["ip"], "45.33.21.10")

    def test_invalid_log_returns_none(self):
        log = "This is not a valid security log entry"

        result = log_analyzer.parse_log_entry(log)

        self.assertIsNone(result)

    def test_brute_force_threshold(self):
        failed_attempts = {
            "45.33.21.10": 3,
            "103.45.22.8": 1
        }

        suspicious_ips = [
            ip for ip, count in failed_attempts.items()
            if count >= log_analyzer.BRUTE_FORCE_THRESHOLD
        ]

        self.assertIn("45.33.21.10", suspicious_ips)
        self.assertNotIn("103.45.22.8", suspicious_ips)

    def test_password_spray_detection(self):
        failed_users_by_ip = {
            "10.10.10.50": {"admin", "alice", "bob", "test"},
            "45.33.21.10": {"root"}
        }

        password_spray_ips = [
            ip for ip, users in failed_users_by_ip.items()
            if len(users) >= log_analyzer.PASSWORD_SPRAY_THRESHOLD
        ]

        self.assertIn("10.10.10.50", password_spray_ips)
        self.assertNotIn("45.33.21.10", password_spray_ips)

    def test_targeted_account_detection(self):
        failed_users = {
            "root": 3,
            "admin": 1,
            "alice": 1
        }

        targeted_accounts = [
            user for user, count in failed_users.items()
            if count >= log_analyzer.TARGETED_ACCOUNT_THRESHOLD
        ]

        self.assertIn("root", targeted_accounts)
        self.assertNotIn("admin", targeted_accounts)


if __name__ == "__main__":
    unittest.main()
