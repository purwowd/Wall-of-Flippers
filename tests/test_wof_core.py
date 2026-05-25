import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils import wof_library as library
from utils import wof_trust as trust
from utils import wof_platform as platform
from utils import wof_cache as cache
from utils import wof_rssi_geo as rssi_geo


class TestWoFCore(unittest.TestCase):
    def test_normalize_hci(self):
        self.assertEqual(library.normalize_hci("hci0"), 0)
        self.assertEqual(library.normalize_hci("1"), 1)
        self.assertEqual(library.normalize_hci(""), 0)

    def test_match_flipper_uid_black(self):
        uid, color, matched = library._match_flipper_uid(
            "00003081-0000-1000-8000-00805f9b34fb"
        )
        self.assertTrue(matched)
        self.assertEqual(color, "B")

    def test_classify_by_name(self):
        is_f, det = library._classify_flipper(
            "Flipper Lab",
            "aa:bb:cc:dd:ee:ff",
            "00003082-0000-1000-8000-00805f9b34fb",
        )
        self.assertTrue(is_f)
        self.assertEqual(det, "Name")

    def test_classify_by_mac(self):
        is_f, det = library._classify_flipper(
            "UNK",
            "0c:fa:22:11:22:33",
            "00003081-0000-1000-8000-00805f9b34fb",
        )
        self.assertTrue(is_f)
        self.assertEqual(det, "Address")

    def test_trust_high(self):
        score = trust.trust_score(
            "Flipper X",
            "0c:fa:22:11:22:33",
            "00003081-0000-1000-8000-00805f9b34fb",
            "Name",
            "B",
        )
        self.assertEqual(score, "High")

    def test_trust_spoof(self):
        score = trust.trust_score("UNK", "aa:bb:cc:dd:ee:ff", "UNK", "Unknown", "UNK")
        self.assertEqual(score, "Spoof?")

    def test_forbidden_pattern(self):
        cache.wof_data["forbidden_packets"] = [
            {"PCK": "4c000719010_2055_______________", "TYPE": "BLE_APPLE_DEVICE_POPUP_CLOSE"},
        ]
        packet = "4c00071901012055abcdef"
        forbidden = cache.wof_data["forbidden_packets"][0]
        matched = all(
            p1 == p2 or p2 == "_"
            for p1, p2 in zip(packet, forbidden["PCK"])
        )
        self.assertTrue(matched)

    def test_platform_darwin_is_bleak(self):
        if sys.platform == "darwin":
            self.assertTrue(platform.uses_bleak())

    def test_rssi_distance_and_bearing(self):
        d = rssi_geo.rssi_to_distance_m(-50)
        self.assertIsNotNone(d)
        self.assertGreater(d, 0)
        self.assertLessEqual(d, 40)
        b1 = rssi_geo.mac_bearing_deg("aa:bb:cc:dd:ee:ff")
        b2 = rssi_geo.mac_bearing_deg("aa:bb:cc:dd:ee:ff")
        self.assertEqual(b1, b2)
        self.assertGreaterEqual(b1, 0)
        self.assertLess(b1, 360)

    def test_build_snapshot_structure(self):
        from utils import wof_engine as engine
        cache.wof_data["live_flippers"] = []
        cache.wof_data["scan_ble_devices"] = [
            {
                "name": "BLE ···aabbcc",
                "mac": "aa:bb:cc:dd:ee:ff",
                "rssi": -55,
                "is_flipper": True,
                "role": "Flipper",
                "trust": "Medium",
            },
        ]
        snap = engine.build_snapshot({"ok": True})
        self.assertIn("stats", snap)
        self.assertIn("online", snap)
        self.assertIn("ble_devices", snap)
        self.assertIn("archive_est_usd", snap["stats"])
        self.assertIn("platform", snap)
        ble = snap["ble_devices_all"][0]
        self.assertIn("est_distance_m", ble)
        self.assertIn("bearing_deg", ble)
        self.assertTrue(ble["is_flipper"])


if __name__ == "__main__":
    unittest.main()
