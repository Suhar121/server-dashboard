import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import config
import database
import routers.metrics


class PinnedPortTelegramAlertTests(unittest.TestCase):
    def setUp(self):
        config.alert_last_sent.clear()
        config.pinned_port_down_alert_state.clear()

    def test_sends_port_down_alert_and_realerts_after_recovery(self):
        sent_messages = []

        with patch.object(database, "list_pinned_ports", return_value=[{"id": 1, "port": 3000}]), \
             patch.object(routers.metrics, "is_local_port_active", side_effect=[False, False, True, True]), \
             patch.object(config, "send_telegram", side_effect=lambda msg: sent_messages.append(msg)):
            routers.metrics.check_pinned_port_alerts()
            routers.metrics.check_pinned_port_alerts()
            routers.metrics.check_pinned_port_alerts()
            routers.metrics.check_pinned_port_alerts()

        self.assertEqual(2, len(sent_messages))
        self.assertTrue(all("3000" in message for message in sent_messages))


if __name__ == "__main__":
    unittest.main()
