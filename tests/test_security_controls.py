import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from api import auth as auth_api
from core.applemail_pool import resolve_applemail_pool_path, save_applemail_pool_json


class SecurityControlsTests(unittest.TestCase):
    def test_uninitialized_api_helper_blocks_non_auth_api(self):
        self.assertTrue(auth_api.should_block_uninitialized_api("/api/accounts", has_password=False))
        self.assertFalse(auth_api.should_block_uninitialized_api("/api/auth/status", has_password=False))
        self.assertFalse(auth_api.should_block_uninitialized_api("/dashboard", has_password=False))
        self.assertFalse(auth_api.should_block_uninitialized_api("/api/accounts", has_password=True))

    def test_password_hashing_accepts_legacy_sha256_and_new_scrypt(self):
        legacy_hash = hashlib.sha256("secret123".encode("utf-8")).hexdigest()

        self.assertTrue(auth_api._verify_pw("secret123", legacy_hash))

        new_hash = auth_api._hash_pw("secret123")
        self.assertTrue(new_hash.startswith("scrypt$"))
        self.assertTrue(auth_api._verify_pw("secret123", new_hash))
        self.assertFalse(auth_api._verify_pw("wrong-password", new_hash))

    def test_save_applemail_pool_rejects_pool_dir_outside_project(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            previous_cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                with self.assertRaisesRegex(ValueError, "邮箱池目录必须位于项目目录内"):
                    save_applemail_pool_json(
                        "demo@example.com----password----client-id----refresh-token",
                        pool_dir="../outside",
                        filename="applemail_demo.json",
                    )
            finally:
                os.chdir(previous_cwd)

    def test_resolve_applemail_pool_path_rejects_nested_pool_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            previous_cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                Path("mail").mkdir(exist_ok=True)
                Path("mail/applemail_demo.json").write_text("[]", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "邮箱池文件名不合法"):
                    resolve_applemail_pool_path(pool_dir="mail", pool_file="../applemail_demo.json")
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
