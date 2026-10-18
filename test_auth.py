import unittest
import auth_service as svc


class TestRegistration(unittest.TestCase):
    def setUp(self):
        svc.USERS.clear()

    def test_successful_registration(self):
        code, body = svc.register_user("alice@example.com", "StrongPass1234")
        self.assertEqual(code, 201)
        self.assertEqual(body["status"], "pending_verification")

    def test_duplicate_registration(self):
        svc.register_user("alice@example.com", "StrongPass1234")
        code, _ = svc.register_user("alice@example.com", "StrongPass1234")
        self.assertEqual(code, 409)

    def test_weak_password_rejected(self):
        code, _ = svc.register_user("bob@example.com", "short")
        self.assertEqual(code, 400)

    def test_password_hash_verifies(self):
        stored = svc.hash_password("StrongPass1234")
        self.assertTrue(svc.verify_password("StrongPass1234", stored))
        self.assertFalse(svc.verify_password("wrong", stored))


if __name__ == "__main__":
    unittest.main()
