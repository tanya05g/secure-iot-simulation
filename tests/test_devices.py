import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import LINK_GATEWAY_CLOUD, LINK_SENSOR_GATEWAY, MODE_INSECURE, MODE_SECURE
from devices.sensors import TemperatureHumiditySensor
from security.encryption import is_envelope
from simulation import (SENSOR_IDS, build_system, legitimate_user_query,
                        run_traffic)


class TestSensors(unittest.TestCase):
    def test_readings_are_realistic(self):
        sensor = TemperatureHumiditySensor("T1", MODE_INSECURE, seed=7)
        for _ in range(200):
            p = sensor.read()
            self.assertTrue(10.0 < p["temperature"] < 40.0)
            self.assertTrue(0.0 <= p["humidity"] <= 100.0)
            self.assertEqual(p["device_id"], "T1")
            self.assertIn("timestamp", p)

    def test_secure_sensor_requires_credentials(self):
        with self.assertRaises(ValueError):
            TemperatureHumiditySensor("T1", MODE_SECURE)

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            build_system("bogus")


class TestInsecureFlow(unittest.TestCase):
    def setUp(self):
        self.system = build_system(MODE_INSECURE, fast_hashing=True)

    def test_data_reaches_cloud_in_plaintext(self):
        for sensor in self.system.sensors:
            self.assertTrue(sensor.send(self.system.network, self.system.gateway).accepted)
        self.assertEqual(len(self.system.cloud.records), len(SENSOR_IDS))
        wire = self.system.network.captured[LINK_SENSOR_GATEWAY][0]
        self.assertIn("temperature", wire)          # anyone can read it
        self.assertFalse(is_envelope(wire))

    def test_anyone_can_query_cloud(self):
        self.system.sensors[0].send(self.system.network, self.system.gateway)
        self.assertTrue(self.system.cloud.query_data(None).accepted)

    def test_run_traffic_reports_counts(self):
        stats = run_traffic(self.system, duration=0.3, interval=0.1, verbose=False)
        self.assertGreater(stats["sent"], 0)
        self.assertEqual(stats["sent"], stats["accepted"])


class TestSecureFlow(unittest.TestCase):
    def setUp(self):
        self.system = build_system(MODE_SECURE, fast_hashing=True)
        self.net, self.gw = self.system.network, self.system.gateway

    def test_legitimate_sensors_still_work(self):
        for sensor in self.system.sensors:
            result = sensor.send(self.net, self.gw)
            self.assertTrue(result.accepted, result.reason)
        self.assertEqual(len(self.system.cloud.records), len(SENSOR_IDS))

    def test_traffic_is_encrypted_on_both_links(self):
        self.system.sensors[0].send(self.net, self.gw)
        for link in (LINK_SENSOR_GATEWAY, LINK_GATEWAY_CLOUD):
            packet = self.net.captured[link][0]
            self.assertTrue(is_envelope(packet))
            self.assertNotIn("temperature", packet)  # payload hidden

    def test_gateway_rejects_plaintext(self):
        result = self.gw.receive({"device_id": "TEMP_HUM_01", "timestamp": 1.0,
                                  "temperature": 22.0, "humidity": 40.0})
        self.assertFalse(result.accepted)
        self.assertEqual(len(self.system.cloud.records), 0)

    def test_revoked_sensor_cannot_authenticate_or_send(self):
        sensor = self.system.sensors[0]
        self.assertTrue(sensor.send(self.net, self.gw).accepted)
        self.system.authenticator.revoke_device(sensor.device_id)
        sensor.token = None
        self.assertFalse(sensor.authenticate(self.gw))
        self.assertFalse(sensor.send(self.net, self.gw).accepted)

    def test_revoked_token_stops_working_immediately(self):
        sensor = self.system.sensors[0]
        sensor.send(self.net, self.gw)
        self.system.authenticator.revoke_device(sensor.device_id)
        self.assertFalse(sensor.send(self.net, self.gw).accepted)

    def test_authorised_analyst_can_read(self):
        self.system.sensors[0].send(self.net, self.gw)
        result = legitimate_user_query(self.system)
        self.assertTrue(result.accepted)
        self.assertEqual(len(result.data), 1)

    def test_cloud_stats_processing(self):
        for _ in range(3):
            self.system.sensors[0].send(self.net, self.gw)
        token = self.system.access_control.login("admin", "admin-demo-pass")
        stats = self.system.cloud.get_stats(token)
        self.assertTrue(stats.accepted)
        self.assertEqual(stats.data["total_records"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
