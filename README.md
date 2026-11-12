# Secure IoT Simulation: Attack and Defence Using Cryptography and Access Control

A beginner-friendly, software-only Python project. Virtual temperature/humidity
sensors send data through a gateway to a cloud server. The same three attacks
are run against an **insecure** system and a **secure** system, and a report
compares how often each attack succeeds.

## Installation

Requires Python 3.9+ (works in GitHub Codespaces, no extra setup).

```bash
pip install -r requirements.txt      # installs the 'cryptography' library
```

## Running (from the repository root)

```bash
python -m unittest discover -s tests -v      # 42 unit tests
python main.py --mode insecure --duration 5  # baseline: attacks succeed
python main.py --mode secure --duration 5    # defended: attacks fail
python main.py --mode compare --duration 5   # runs both and prints the report
```

Options: `--duration` seconds of sensor traffic, `--interval` seconds between
readings, `--attempts` attempts per attack (default 10).

After both modes have run, the comparison report is printed and saved to
`reports/output/comparison.txt` and `reports/output/comparison.csv`
(re-print it any time with `python -m reports.comparison`).

## How the system works

```
 Sensors  --(link 1)-->  Gateway  --(link 2)-->  Cloud server
   ^                        ^                        ^
   +------ attacker sniffs and injects on the network, or queries the cloud
```

| Folder / file | Purpose |
|---|---|
| `devices/sensors.py` | Virtual temperature + humidity sensors |
| `devices/gateway.py` | Gateway and the simulated network (records traffic an attacker could sniff) |
| `cloud/server.py` | Stores and processes data, answers queries |
| `security/encryption.py` | AES-256-GCM encryption, HMAC-SHA256, encrypt-then-MAC envelopes |
| `security/authentication.py` | Device registration, challenge-response login, session tokens, replay protection |
| `security/access_control.py` | Salted password hashing (PBKDF2), RBAC roles and permissions, login lockout |
| `attacks/*.py` | Replay, spoofing and unauthorized-access attacks |
| `reports/comparison.py` | Builds the comparison table and CSV |
| `simulation.py` | Builds a full system in either mode and runs traffic |
| `main.py` | Entry point |

### Insecure mode
No authentication, no encryption, no access control. Packets are readable
plaintext and any request is answered.

### Secure mode
1. **Device authentication**: each device has secret keys from the trusted registry. It logs in with challenge-response (the key is never sent) and gets a session token.
2. **AES-256-GCM** encrypts every payload on both links (sensor to gateway, gateway to cloud).
3. **HMAC-SHA256** covers the header and ciphertext, so any modification is detected before decryption.
4. **Replay protection**: every message has a timestamp and a one-time nonce; old, future or repeated messages are rejected.
5. **RBAC**: roles `admin`, `analyst`, `sensor`, `gateway`, `guest`. Only `admin` and `analyst` may read data; `guest` has no permissions. Three wrong passwords lock an account.

## The attacks and what "success" means

| Attack | What the attacker does | Counted as success when |
|---|---|---|
| Replay | Records real packets from the network and resends them | A duplicate record is stored in the cloud |
| Data spoofing | Forges readings (55 C+) pretending to be a real sensor | The fake reading is stored in the cloud |
| Unauthorized access | No credentials, forged token, guest account, password guessing | The cloud returns sensor data |

Success rates are measured by checking the cloud database after each attempt.
Nothing in the report is hardcoded.

## Expected result

| Attack | Insecure | Secure |
|---|---|---|
| Replay | 100% | 0% |
| Data spoofing | 100% | 0% |
| Unauthorized access | 100% | 0% |

Legitimate sensors and the authorised analyst keep working in secure mode.

## Limitations (for your report)

- Everything runs in one process; the "network" is simulated.
- Keys live in memory; a real system needs secure key storage and rotation.
- Repeated wrong passwords lock the admin account, which an attacker could abuse to deny the real admin access.
- Demo user passwords in `simulation.py` are for the simulation only.
- All attacks target only this local simulation.
