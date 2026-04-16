import os
import unittest

from core import secret_crypto


class SecretCryptoTests(unittest.TestCase):
    def setUp(self):
        self._old_key = os.environ.get("APP_DATA_ENCRYPTION_KEY")
        os.environ["APP_DATA_ENCRYPTION_KEY"] = "unit-test-secret-key"
        secret_crypto._jwe_key.cache_clear()

    def tearDown(self):
        if self._old_key is None:
            os.environ.pop("APP_DATA_ENCRYPTION_KEY", None)
        else:
            os.environ["APP_DATA_ENCRYPTION_KEY"] = self._old_key
        secret_crypto._jwe_key.cache_clear()

    def test_encrypt_and_decrypt_roundtrip(self):
        encrypted = secret_crypto.encrypt_text("demo-secret")

        self.assertTrue(secret_crypto.is_encrypted_text(encrypted))
        self.assertNotEqual(encrypted, "demo-secret")
        self.assertEqual(secret_crypto.decrypt_text(encrypted), "demo-secret")

    def test_decrypt_plaintext_keeps_legacy_values(self):
        self.assertEqual(secret_crypto.decrypt_text("legacy-plain-text"), "legacy-plain-text")

    def test_encrypt_text_is_idempotent_for_existing_ciphertext(self):
        encrypted = secret_crypto.encrypt_text("demo-secret")

        self.assertEqual(secret_crypto.encrypt_text(encrypted), encrypted)

    def test_decrypt_raises_when_key_does_not_match(self):
        encrypted = secret_crypto.encrypt_text("demo-secret")
        os.environ["APP_DATA_ENCRYPTION_KEY"] = "another-unit-test-key"
        secret_crypto._jwe_key.cache_clear()

        with self.assertRaisesRegex(RuntimeError, "敏感数据解密失败"):
            secret_crypto.decrypt_text(encrypted)


if __name__ == "__main__":
    unittest.main()
