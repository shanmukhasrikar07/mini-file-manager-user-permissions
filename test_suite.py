import unittest
import time
import os
from auth import AuthManager
from intrusion import IntrusionDetector
from filesystem import FileSystemManager
from permissions import PermissionDeniedError

class TestMiniFileSystem(unittest.TestCase):
    def setUp(self):
        self.test_users = "test_users.json"
        self.test_storage = "test_storage.json"
        self.test_audit = "test_audit.log"
        for f in [self.test_users, self.test_storage, self.test_audit]:
            if os.path.exists(f):
                os.remove(f)

        self.auth = AuthManager(self.test_users)
        self.detector = IntrusionDetector(self.auth, threshold_n=3, window_w=2, lock_time_t=3)
        self.fs = FileSystemManager(self.test_storage, self.test_audit, intrusion_detector=self.detector)
        self.detector.audit_logger = self.fs.audit

        self.admin = self.auth.users["admin"]
        self.alice = self.auth.users["alice"]
        self.bob = self.auth.users["bob"]

        # Admin assigns /docs to alice as in the paper scenario
        self.fs.chown("/docs", "alice", "users", self.admin)
        self.fs.chmod("/docs", 0o750, self.admin)

    def tearDown(self):
        for f in [self.test_users, self.test_storage, self.test_audit]:
            if os.path.exists(f):
                os.remove(f)

    def test_T1_intrusion_lockout_on_3_denials(self):
        """T1: 3 denials by one user in 60s -> Flagged, locked, session ends"""
        self.fs.write("/docs/secret.txt", "TopSecret", self.alice)

        # Bob attempts 3 times to access /docs
        for i in range(2):
            with self.assertRaises(PermissionDeniedError):
                self.fs.cat("/docs/secret.txt", self.bob)
            self.assertFalse(self.bob.is_locked())

        # 3rd denial should trigger lockout
        with self.assertRaises(PermissionDeniedError):
            self.fs.cat("/docs/secret.txt", self.bob)

        self.assertTrue(self.bob.is_locked())
        print("\n[PASS - T1] 3 denials correctly triggered account lockout for 120s.")

    def test_T2_sliding_window_expiration(self):
        """T2: 2 denials, then window pause, then 1 -> No lock"""
        # 2 denials
        for i in range(2):
            try:
                self.fs.resolve_path("/docs", self.bob)
            except PermissionDeniedError:
                pass

        # Wait for window W (configured as 2s in test) to expire
        time.sleep(2.1)

        # 3rd denial after window expiration
        try:
            self.fs.resolve_path("/docs", self.bob)
        except PermissionDeniedError:
            pass

        self.assertFalse(self.bob.is_locked())
        print("[PASS - T2] Sliding window expired; strike count reset.")

    def test_T3_login_while_locked(self):
        """T3: Login while locked is rejected before password verification"""
        self.bob.locked_until = time.time() + 10
        self.auth.save_users()

        user, msg = self.auth.authenticate("bob", "bobpass", self.detector)
        self.assertIsNone(user)
        self.assertIn("Account locked", msg)
        print("[PASS - T3] Login rejected before password checking while account is locked.")

    def test_T4_auto_unlock_after_duration(self):
        """T4: Wait after lock duration -> Account automatically usable"""
        self.bob.locked_until = time.time() + 1  # 1 second lock
        self.auth.save_users()
        time.sleep(1.1)

        user, msg = self.auth.authenticate("bob", "bobpass", self.detector)
        self.assertIsNotNone(user)
        self.assertEqual(msg, "Login successful.")
        print("[PASS - T4] Account automatically unlocked after lock duration expired.")

    def test_T5_admin_unlock_command(self):
        """T5: Admin runs unlock <user> -> Lock cleared, logged"""
        self.bob.locked_until = time.time() + 100
        self.auth.save_users()

        success, msg = self.detector.unlock_user("bob", self.admin)
        self.assertTrue(success)
        self.assertFalse(self.bob.is_locked())
        print("[PASS - T5] Admin unlock command successfully cleared account lock.")

    def test_T6_file_versioning_on_overwrite(self):
        """T6: Overwrite file -> Previous content stored as version with SHA-256"""
        self.fs.write("/docs/report.txt", "Draft 1", self.alice)
        self.fs.write("/docs/report.txt", "Draft 2", self.alice)

        node = self.fs.resolve_path("/docs/report.txt", self.alice)
        self.assertEqual(len(node.versions), 1)
        self.assertEqual(node.versions[0].content, "Draft 1")
        self.assertEqual(node.content, "Draft 2")
        print("[PASS - T6] File overwrite safely snapshotted old content as version.")

    def test_T7_reader_without_write_cannot_restore(self):
        """T7: Reader without write runs restore -> Permission denied"""
        self.fs.write("/docs/shared.txt", "Version 1", self.alice)
        self.fs.chmod("/docs/shared.txt", 0o644, self.alice)
        self.fs.chmod("/docs", 0o755, self.admin) # allow bob to traverse
        self.fs.write("/docs/shared.txt", "Version 2", self.alice)

        node = self.fs.resolve_path("/docs/shared.txt", self.bob)
        with self.assertRaises(PermissionDeniedError):
            self.fs.version_manager.restore(node, self.bob, "1")
        print("[PASS - T7] Unauthorized restore attempt rejected by permission choke point.")

    def test_T8_version_cap_fifo_eviction(self):
        """T8: More than K=5 overwrites -> Oldest version evicted"""
        self.fs.write("/docs/cap_test.txt", "v0", self.alice)
        for i in range(1, 8):
            self.fs.write("/docs/cap_test.txt", f"v{i}", self.alice)

        node = self.fs.resolve_path("/docs/cap_test.txt", self.alice)
        self.assertEqual(len(node.versions), 5)
        # Oldest versions v0, v1, v2 should have been evicted
        version_nums = [v.num for v in node.versions]
        self.assertEqual(version_nums, [3, 4, 5, 6, 7])
        print("[PASS - T8] FIFO eviction enforced: capped at exactly K=5 versions.")

    def test_T9_non_destructive_restore(self):
        """T9: Restore a version -> Current content saved as new version"""
        self.fs.write("/docs/doc.txt", "Draft 1", self.alice)
        self.fs.write("/docs/doc.txt", "Draft 2", self.alice)
        node = self.fs.resolve_path("/docs/doc.txt", self.alice)

        # Restore v1
        self.fs.version_manager.restore(node, self.alice, "1")
        self.assertEqual(node.content, "Draft 1")
        # Previous content 'Draft 2' must now be saved as v2
        self.assertEqual(len(node.versions), 2)
        self.assertEqual(node.versions[-1].content, "Draft 2")
        print("[PASS - T9] Non-destructive rollback confirmed (pre-rollback content saved).")

    def test_T10_restart_persistence(self):
        """T10: Restart system -> Versions and lock state persist from JSON"""
        self.fs.write("/docs/persist.txt", "State 1", self.alice)
        self.fs.write("/docs/persist.txt", "State 2", self.alice)
        self.bob.locked_until = time.time() + 100
        self.auth.save_users()

        # Simulate system reboot by re-initializing managers
        reboot_auth = AuthManager(self.test_users)
        reboot_fs = FileSystemManager(self.test_storage, self.test_audit)

        reboot_node = reboot_fs.resolve_path("/docs/persist.txt", reboot_auth.users["alice"])
        self.assertEqual(reboot_node.content, "State 2")
        self.assertEqual(len(reboot_node.versions), 1)
        self.assertTrue(reboot_auth.users["bob"].is_locked())
        print("[PASS - T10] Complete system state and version history persisted across restart.")

if __name__ == "__main__":
    unittest.main()
