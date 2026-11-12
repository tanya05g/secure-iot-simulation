"""Unauthorized access: an outsider (or a low-privilege user) tries to read
the stored sensor data from the cloud.

Techniques, rotated across attempts:
  1. no credentials at all
  2. a forged session token
  3. a genuine but low-privilege 'guest' account (privilege escalation)
  4. password guessing against the admin account

Success = the cloud returned the sensor data to the attacker.
"""
import secrets

from common import AttackResult

NAME = "Unauthorized Access"
GUESSES = ["admin", "password123", "letmein"]


def run(system, attempts: int = 10) -> AttackResult:
    result = AttackResult(NAME, system.mode)
    guest_password = system.demo_users["guest"][0]

    for i in range(attempts):
        kind = i % 4
        if kind == 0:
            technique, token = "no credentials", None
        elif kind == 1:
            technique, token = "forged session token", secrets.token_hex(16)
        elif kind == 2:
            technique = "guest account reading telemetry"
            token = system.access_control.login("guest", guest_password)
        else:
            technique = "password guessing on admin"
            token = None
            for guess in GUESSES:
                token = system.access_control.login("admin", guess)
                if token:
                    break
        response = system.cloud.query_data(token)
        got_data = response.accepted and bool(response.data)
        result.record(technique, got_data, response.reason)
    return result
