import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import config
import routers.docker_manager


class DockerTelegramAlertTests(unittest.TestCase):
    def setUp(self):
        config.docker_container_alert_state.clear()

    def test_sends_start_stop_and_error_alerts(self):
        sent_messages = []

        snapshots = [
            [
                {
                    "id": "abc123",
                    "name": "web",
                    "image": "nginx:latest",
                    "state": "running",
                    "status": "Up 2 seconds",
                    "ports": "0.0.0.0:8080->80/tcp",
                }
            ],
            [
                {
                    "id": "abc123",
                    "name": "web",
                    "image": "nginx:latest",
                    "state": "exited",
                    "status": "Exited (0) 1 second ago",
                    "ports": "0.0.0.0:8080->80/tcp",
                }
            ],
            [
                {
                    "id": "abc123",
                    "name": "web",
                    "image": "nginx:latest",
                    "state": "running",
                    "status": "Up 1 second",
                    "ports": "0.0.0.0:8080->80/tcp",
                }
            ],
            [
                {
                    "id": "abc123",
                    "name": "web",
                    "image": "nginx:latest",
                    "state": "exited",
                    "status": "Exited (1) 1 second ago",
                    "ports": "0.0.0.0:8080->80/tcp",
                }
            ],
        ]

        with patch.object(routers.docker_manager, "list_docker_container_snapshots", side_effect=snapshots), \
             patch.object(config, "send_telegram", side_effect=lambda msg: sent_messages.append(msg)):
            routers.docker_manager.check_docker_container_alerts(force=True)
            routers.docker_manager.check_docker_container_alerts(force=True)
            routers.docker_manager.check_docker_container_alerts(force=True)
            routers.docker_manager.check_docker_container_alerts(force=True)

        self.assertEqual(3, len(sent_messages))
        self.assertIn("stopped", sent_messages[0].lower())
        self.assertIn("started", sent_messages[1].lower())
        self.assertIn("error", sent_messages[2].lower())
        self.assertTrue(all("8080" in msg or "80" in msg for msg in sent_messages))


if __name__ == "__main__":
    unittest.main()
