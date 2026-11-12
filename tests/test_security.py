import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks import replay_attack, spoofing_attack, unauthorized_access
from common import MODE_INSECURE, MODE_SECURE
from security.access_control import AccessControl, role_allows
from security.authentication import (Authenticator, ReplayGuard,
                                     compute_challenge_response)
from security.encryption import (IntegrityError, compute_hmac, decrypt,
                                 encrypt, generate_key, open_message,
                                 seal_message, verify_envelope, verify_hmac)
from simulation import build_system, run_traffic


class TestAesAndHmac(unittest.TestCase):
    def test_aes_round_trip(self):
        key = generate_key()
        blob = encrypt(key, b"temperature=22.5")
        self.assertEqual(decrypt(key, blob), b"temperature=22.5")
        self.assertNotIn(b"temperature", blob)

    def test_same_plaintext_gives_different_ciphertext(self):
        key = generate_key()
        self.assertNotEqual(encrypt(key, b"abc"), encrypt(key, b"abc"))

    def test_wrong_key_fails(self):
        blob = encrypt(generate_key(), b"secret")
        with self.assertRaises(IntegrityError):
            decrypt(generate_key(), blob)

    def test_tampered_ciphertext_fails(self):
        key = generate_key()
        blob = bytearray(encrypt(key, b"secret data"))
        blob[-1] ^= 0x01
        with self.assertRaises(IntegrityError):
            decrypt(key, bytes(blob))

    def test_bad_key_size(self):
        with self.assertRaises(ValueError):
            encrypt(b"short", b"x")

    def test_hmac(self):
        key = generate_key()
        tag = compute_hmac(key, b"data")
        self.assertTrue(verify_hmac(key, b"data", tag))
        self.assertFalse(verify_hmac(key, b"data!", tag))
        self.assertFalse(verify_hmac(generate_key(), b"data", tag))


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.enc, self.mac = generate_key(), generate_key()
        self.payload = {"device_id": "T1", "temperature": 21.0}
        self.env = seal_message(self.enc, self.mac, "T1", self.payload, "tok")

    def test_authorised_recipient_can_open(self):
        self.assertEqual(open_message(self.enc, self.mac, self.env), self.payload)

    def test_modified_ciphertext_fails_integrity(self):
        self.env["ciphertext"] = ("A" if self.env["ciphertext"][0] != "A" else "B") \
            + self.env["ciphertext"][1:]
        with self.assertRaises(IntegrityError):
            open_message(self.enc, self.mac, self.env)

    def test_modified_header_fails_integrity(self):
        self.env["device_id"] = "T2"
        self.assertFalse(verify_envelope(self.mac, self.env))

    def test_malformed_envelope_does_not_crash(self):
        self.assertFalse(verify_envelope(self.mac, {"mac": "x"}))
        self.assertFalse(verify_envelope(self.mac, {}))

    def test_wrong_mac_key_fails(self):
        with self.assertRaises(IntegrityError):
            open_message(self.enc, generate_key(), self.env)


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.auth = Authenticator()
        self.creds = self.auth.register_device("S1")

    def _login(self, key=None):
        challenge = self.auth.issue_challenge("S1")
        return self.auth.verify_response(
            "S1", compute_challenge_response(key or self.creds.mac_key, challenge))

    def test_challenge_response_success(self):
        token = self._login()
        self.assertIsNotNone(token)
        self.assertTrue(self.auth.validate_token(token, "S1"))
        self.assertFalse(self.auth.validate_token(token, "OTHER"))

    def test_wrong_key_fails(self):
        self.assertIsNone(self._login(generate_key()))

    def test_challenge_is_single_use(self):
        challenge = self.auth.issue_challenge("S1")
        response = compute_challenge_response(self.creds.mac_key, challenge)
        self.assertIsNotNone(self.auth.verify_response("S1", response))
        self.assertIsNone(self.auth.verify_response("S1", response))

    def test_unknown_device_gets_no_challenge(self):
        self.assertIsNone(self.auth.issue_challenge("NOPE"))

    def test_revoked_device_cannot_authenticate(self):
        token = self._login()
        self.auth.revoke_device("S1")
        self.assertIsNone(self.auth.issue_challenge("S1"))
        self.assertFalse(self.auth.validate_token(token, "S1"))
        self.assertIsNone(self.auth.get_credentials("S1"))

    def test_duplicate_registration_rejected(self):
        with self.assertRaises(ValueError):
            self.auth.register_device("S1")


class TestReplayGuard(unittest.TestCase):
    def test_fresh_then_duplicate(self):
        guard, now = ReplayGuard(window=30), 1000.0
        self.assertTrue(guard.check("D", "n1", now, now)[0])
        ok, reason = guard.check("D", "n1", now, now + 1)
        self.assertFalse(ok)
        self.assertIn("replay", reason)

    def test_stale_and_future_rejected(self):
        guard, now = ReplayGuard(window=30), 1000.0
        self.assertFalse(guard.check("D", "a", now - 60, now)[0])
        self.assertFalse(guard.check("D", "b", now + 60, now)[0])
        self.assertFalse(guard.check("D", "c", "junk", now)[0])


class TestAccessControl(unittest.TestCase):
    def setUp(self):
        self.ac = AccessControl(iterations=1000)
        self.ac.register_user("alice", "pw-alice", "analyst")
        self.ac.register_user("gus", "pw-gus", "guest")

    def test_login_and_roles(self):
        token = self.ac.login("alice", "pw-alice")
        self.assertEqual(self.ac.validate(token), ("alice", "analyst"))
        self.assertTrue(self.ac.is_allowed(token, "read:telemetry"))
        self.assertFalse(self.ac.is_allowed(token, "manage:devices"))

    def test_guest_has_no_permissions(self):
        token = self.ac.login("gus", "pw-gus")
        self.assertFalse(self.ac.is_allowed(token, "read:telemetry"))

    def test_wrong_password_and_lockout(self):
        for _ in range(3):
            self.assertIsNone(self.ac.login("alice", "wrong"))
        self.assertTrue(self.ac.is_locked("alice"))
        self.assertIsNone(self.ac.login("alice", "pw-alice"))  # locked out
        self.ac.reset_lockout("alice")
        self.assertIsNotNone(self.ac.login("alice", "pw-alice"))

    def test_invalid_token_and_role(self):
        self.assertIsNone(self.ac.validate("not-a-token"))
        self.assertFalse(self.ac.is_allowed(None, "read:telemetry"))
        self.assertFalse(role_allows("sensor", "read:telemetry"))
        with self.assertRaises(ValueError):
            self.ac.register_user("x", "y", "superuser")

    def test_passwords_are_salted(self):
        self.ac.register_user("b1", "same", "guest")
        self.ac.register_user("b2", "same", "guest")
        self.assertNotEqual(self.ac._users["b1"]["hash"], self.ac._users["b2"]["hash"])


class TestAttacksInBothModes(unittest.TestCase):
    ATTEMPTS = 8

    def _prepared(self, mode):
        system = build_system(mode, fast_hashing=True)
        run_traffic(system, duration=0.3, interval=0.1, verbose=False)
        return system

    def test_all_attacks_succeed_in_insecure_mode(self):
        for module in (replay_attack, spoofing_attack, unauthorized_access):
            system = self._prepared(MODE_INSECURE)
            res = module.run(system, self.ATTEMPTS)
            self.assertEqual(res.successes, self.ATTEMPTS, module.NAME)

    def test_all_attacks_fail_in_secure_mode(self):
        for module in (replay_attack, spoofing_attack, unauthorized_access):
            system = self._prepared(MODE_SECURE)
            res = module.run(system, self.ATTEMPTS)
            self.assertEqual(res.attempts, self.ATTEMPTS)
            self.assertEqual(res.successes, 0, module.NAME)

    def test_secure_mode_stores_no_fake_data(self):
        system = self._prepared(MODE_SECURE)
        legit_count = len(system.cloud.records)
        replay_attack.run(system, self.ATTEMPTS)
        spoofing_attack.run(system, self.ATTEMPTS)
        self.assertEqual(len(system.cloud.records), legit_count)
        self.assertFalse(any(r["temperature"] >= 55 for r in system.cloud.records))

    def test_legitimate_traffic_works_after_attacks(self):
        system = self._prepared(MODE_SECURE)
        for module in (replay_attack, spoofing_attack, unauthorized_access):
            module.run(system, self.ATTEMPTS)
        stats = run_traffic(system, duration=0.3, interval=0.1, verbose=False)
        self.assertEqual(stats["sent"], stats["accepted"])

    def test_stale_message_with_valid_token_is_rejected(self):
        system = self._prepared(MODE_SECURE)
        sensor = system.sensors[0]
        payload = sensor.read()
        env = seal_message(sensor.credentials.enc_key, sensor.credentials.mac_key,
                           sensor.device_id, payload, sensor.token,
                           timestamp=time.time() - 1000)
        result = system.gateway.receive(env)
        self.assertFalse(result.accepted)
        self.assertIn("stale", result.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
